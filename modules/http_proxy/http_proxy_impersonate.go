package http_proxy

// Browser-matched upstream fingerprinting for the bettercap HTTP(S) proxy.
//
// Problem: goproxy re-originates every MITM'd request with Go's net/http
// transport. That produces a Go TLS ClientHello (JA3/JA4) and, because the
// upstream leg is HTTP/1.1, no HTTP/2 (Akamai) fingerprint at all. Anti-bot
// edges such as Akamai Bot Manager compare that transport fingerprint against
// the advertised User-Agent / client hints; when they disagree the edge halts
// the request (e.g. 403 with Server: AkamaiNetStorage, X-Edge-Error: halt).
//
// Fix: for in-scope hosts (default: all), re-originate upstream through
// github.com/bogdanfinn/tls-client, which speaks HTTP/2 and reproduces a real
// browser's TLS (JA3/JA4) and HTTP/2 (SETTINGS, WINDOW_UPDATE, priority,
// pseudo-header order) fingerprints. Crucially it also FORWARDS THE CLIENT'S
// HEADERS FAITHFULLY (bettercap's fixRequestHeaders is skipped for these), which
// on its own is what lets most apps through -- the same reason Burp works.
//
// The design separates two concerns:
//   - HTTP faithfulness (target-agnostic): don't rewrite request headers, speak
//     h2 upstream, pass bodies through as identity. The `headers` strategy keeps
//     native clients native ('auto' imposes a Chrome order only on real browser
//     requests). The module-wide `faithful` flag extends this to the stock
//     transport too.
//   - TLS fingerprint impersonation (optional): the Chrome `profile`, only
//     needed for targets that gate on JA3/JA4.
//
// This is a transport-fidelity shim for authorized interception/analysis in a
// controlled sandbox. The impersonated connection carries exactly the request
// the client made; nothing about the request content is forged.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	"github.com/bettercap/bettercap/v2/session"

	"github.com/elazarl/goproxy"
)

// RegisterImpersonationParams registers the impersonation parameters on a
// module under the given prefix ("http.proxy" or "https.proxy").
func RegisterImpersonationParams(mod *session.SessionModule, prefix string) {
	mod.AddParam(session.NewBoolParameter(prefix+".impersonate",
		"false",
		"Re-originate upstream requests with a browser-matched TLS/HTTP2 fingerprint (defeats transport fingerprinting by anti-bot edges such as Akamai)."))

	mod.AddParam(session.NewStringParameter(prefix+".impersonate.profile",
		"chrome_133",
		"",
		"tls-client profile to impersonate upstream (e.g. chrome_131, chrome_133). Match this to the User-Agent you send."))

	mod.AddParam(session.NewStringParameter(prefix+".impersonate.hosts",
		"*",
		"",
		"Comma separated host or host/path globs to impersonate. Default '*' = all hosts (generic, like Burp). Narrow with host ('accounts.zalando.com') or host/path ('accounts.zalando.com/authorize*', trailing * = prefix match)."))

	mod.AddParam(session.NewStringParameter(prefix+".impersonate.headers",
		"auto",
		"(auto|browser|preserve)",
		"Header-order strategy. 'auto': impose Chrome order only on browser requests (Sec-Ch-Ua/Sec-Fetch present), preserve others. 'browser': always Chrome order. 'preserve': never impose an order (faithful forwarding, client-agnostic)."))

	mod.AddParam(session.NewBoolParameter(prefix+".impersonate.verifyupstream",
		"true",
		"Verify upstream TLS certificates on impersonated connections."))

	mod.AddParam(session.NewBoolParameter(prefix+".impersonate.decode",
		"true",
		"Transparently decode gzip/deflate/br responses so injection and logging see identity bodies."))

	mod.AddParam(session.NewBoolParameter(prefix+".faithful",
		"false",
		"Forward requests faithfully: skip bettercap's header rewriting (Accept-Encoding / Upgrade-Insecure-Requests stripping and Pragma injection) for ALL requests on this module, not just impersonated ones."))
}

// ConfigureImpersonation reads the impersonation parameters under prefix and
// (re)configures the proxy accordingly. Call from each module's Configure().
func ConfigureImpersonation(mod *session.SessionModule, prefix string, proxy *HTTPProxy) error {
	// faithful is independent of impersonation: it governs the stock transport
	// too, so read and apply it regardless of whether impersonation is enabled.
	err, faithful := mod.BoolParam(prefix + ".faithful")
	if err != nil {
		return err
	}
	proxy.Faithful = faithful

	err, enabled := mod.BoolParam(prefix + ".impersonate")
	if err != nil {
		return err
	}
	if !enabled {
		return proxy.EnableImpersonation(false, "", "", "", true, true)
	}

	var profileName, hosts, headers string
	var verify, decode bool
	if err, profileName = mod.StringParam(prefix + ".impersonate.profile"); err != nil {
		return err
	} else if err, hosts = mod.StringParam(prefix + ".impersonate.hosts"); err != nil {
		return err
	} else if err, headers = mod.StringParam(prefix + ".impersonate.headers"); err != nil {
		return err
	} else if err, verify = mod.BoolParam(prefix + ".impersonate.verifyupstream"); err != nil {
		return err
	} else if err, decode = mod.BoolParam(prefix + ".impersonate.decode"); err != nil {
		return err
	}
	return proxy.EnableImpersonation(true, profileName, hosts, headers, verify, decode)
}

// Chrome's navigation request header order. fhttp emits headers in this order
// when the HeaderOrderKey pseudo-header is present; any header not listed here
// is appended afterwards in insertion order.
var chromeHeaderOrder = []string{
	"host",
	"connection",
	"pragma",
	"cache-control",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"upgrade-insecure-requests",
	"user-agent",
	"accept",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-user",
	"sec-fetch-dest",
	"referer",
	"accept-encoding",
	"accept-language",
	"cookie",
}

// Chrome's HTTP/2 pseudo-header order.
var chromePseudoOrder = []string{":method", ":authority", ":scheme", ":path"}

// Headers that must not be carried into an HTTP/2 upstream request (hop-by-hop
// and connection-specific), nor echoed back verbatim to the HTTP/1.1 client.
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// Impersonator re-originates MITM'd requests upstream with a browser-matched
// TLS + HTTP/2 fingerprint. It implements goproxy.RoundTripper so it can be
// attached per-request via ctx.RoundTripper, leaving goproxy's response
// handling, JS injection and logging hooks fully intact.
type Impersonator struct {
	sync.Mutex
	proxy       *HTTPProxy
	client      tls_client.HttpClient
	hosts       []string // wildcard scope; empty => all hosts
	decode      bool     // transparently gunzip/inflate responses for injection+logging
	headerMode  string   // auto | browser | preserve
	profileName string   // resolved profile, for logging
}

// clientProfileByName resolves a tls-client profile name (e.g. "chrome_133")
// to its ClientProfile. Falls back to the newest bundled Chrome on miss.
func clientProfileByName(name string) (profiles.ClientProfile, string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return profiles.Chrome_133, "chrome_133"
	}
	if p, ok := profiles.MappedTLSClients[name]; ok {
		return p, name
	}
	return profiles.Chrome_133, "chrome_133 (requested '" + name + "' not found)"
}

// NewImpersonator builds an Impersonator for the given profile/scope. verify
// controls upstream certificate verification (independent of the CA bettercap
// presents to the client). decode transparently decompresses gzip/deflate
// responses so SSL-strip, JS injection and the logging hooks keep seeing
// identity-encoded bodies (this mirrors bettercap's existing Accept-Encoding
// stripping).
func NewImpersonator(p *HTTPProxy, profileName, hosts, headerMode string, verify, decode bool) (*Impersonator, string, error) {
	profile, resolved := clientProfileByName(profileName)

	switch headerMode {
	case "browser", "preserve", "auto":
	default:
		headerMode = "auto"
	}

	opts := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profile),
		tls_client.WithNotFollowRedirects(), // return 3xx to the client, as a proxy must
		tls_client.WithTimeoutSeconds(30),
	}
	if !verify {
		opts = append(opts, tls_client.WithInsecureSkipVerify())
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		return nil, resolved, err
	}

	imp := &Impersonator{
		proxy:       p,
		client:      client,
		decode:      decode,
		headerMode:  headerMode,
		profileName: resolved,
	}
	for _, h := range strings.Split(hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			imp.hosts = append(imp.hosts, h)
		}
	}
	return imp, resolved, nil
}

// EnableImpersonation configures (or disables) browser-matched upstream
// re-origination on the proxy. Called from each module's Configure() after the
// base Configure(), so it does not disturb bettercap's existing signature.
func (p *HTTPProxy) EnableImpersonation(enabled bool, profileName, hosts, headerMode string, verify, decode bool) error {
	if !enabled {
		p.Impersonate = nil
		return nil
	}
	imp, resolved, err := NewImpersonator(p, profileName, hosts, headerMode, verify, decode)
	if err != nil {
		return err
	}
	p.Impersonate = imp
	scope := hosts
	if strings.TrimSpace(scope) == "" {
		scope = "*"
	}
	p.Info("upstream impersonation enabled (profile=%s, hosts=%s, headers=%s, verify-upstream=%v, decode=%v, faithful=%v)",
		resolved, scope, imp.headerMode, verify, decode, p.Faithful)
	return nil
}

// InScope reports whether a request should be impersonated. Each scope entry
// is either a host glob ("accounts.zalando.com", "*.zalando.com") matching any
// path, or host/path ("accounts.zalando.com/authorize") where a trailing "*"
// on the path is a prefix match ("/authorize*") and otherwise the path must
// match exactly.
func (imp *Impersonator) InScope(host, path string) bool {
	host = strings.Split(host, ":")[0]
	if len(imp.hosts) == 0 {
		return true
	}
	for _, expr := range imp.hosts {
		hostPat, pathPat := expr, ""
		if i := strings.IndexByte(expr, '/'); i >= 0 {
			hostPat, pathPat = expr[:i], expr[i:]
		}
		if ok, err := filepath.Match(hostPat, host); err != nil || !ok {
			continue
		}
		if pathPat == "" || matchPath(pathPat, path) {
			return true
		}
	}
	return false
}

// matchPath matches a request path against a scope path pattern. A trailing "*"
// is a prefix match; otherwise the match is exact.
func matchPath(pat, p string) bool {
	if strings.HasSuffix(pat, "*") {
		return strings.HasPrefix(p, strings.TrimSuffix(pat, "*"))
	}
	return p == pat
}

// isBrowserRequest reports whether a request carries browser markers (client
// hints / fetch metadata). Used by the 'auto' header strategy to decide whether
// imposing a Chrome header order is faithful.
func isBrowserRequest(h fhttp.Header) bool {
	return h.Get("Sec-Ch-Ua") != "" || h.Get("Sec-Fetch-Mode") != "" || h.Get("Sec-Fetch-Dest") != ""
}

// RoundTrip satisfies goproxy.RoundTripper: translate the stdlib request into
// an fhttp request, send it over the fingerprinted transport, and translate the
// fhttp response back into a stdlib response for goproxy.
func (imp *Impersonator) RoundTrip(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	imp.Lock()
	defer imp.Unlock()

	if imp.proxy != nil {
		imp.proxy.Info("impersonate[%s] -> %s %s", imp.profileName, req.Method, req.URL.String())
	}

	freq, err := imp.buildUpstreamRequest(req)
	if err != nil {
		if imp.proxy != nil {
			imp.proxy.Warning("impersonate[%s] build-request error for %s: %v", imp.profileName, req.Host, err)
		}
		return nil, err
	}

	fres, err := imp.client.Do(freq)
	if err != nil {
		if imp.proxy != nil {
			imp.proxy.Warning("impersonate[%s] upstream error for %s: %v", imp.profileName, req.Host, err)
		}
		return nil, err
	}

	if imp.proxy != nil {
		// fres.Proto is "HTTP/2.0" when the Chrome ALPN negotiated h2 upstream,
		// "HTTP/1.1" otherwise -- the direct tell that the fingerprint took.
		imp.proxy.Info("impersonate[%s] <- %s proto=%s host=%s", imp.profileName, fres.Status, fres.Proto, req.Host)
	}

	return imp.adaptResponse(req, fres)
}

// buildUpstreamRequest converts a stdlib *http.Request into an fhttp.Request
// carrying the browser header + pseudo-header order and a decodable
// Accept-Encoding.
func (imp *Impersonator) buildUpstreamRequest(req *http.Request) (*fhttp.Request, error) {
	var body io.Reader
	hasBody := req.Body != nil && req.Method != "GET" && req.Method != "HEAD"
	if hasBody {
		body = req.Body
	}

	freq, err := fhttp.NewRequest(req.Method, req.URL.String(), body)
	if err != nil {
		return nil, err
	}
	freq.Host = req.Host
	if hasBody {
		freq.ContentLength = req.ContentLength
	}

	h := make(fhttp.Header)
	for name, values := range req.Header {
		ln := strings.ToLower(name)
		// Skip hop-by-hop, plus Host and Content-Length: over HTTP/2 the
		// authority is carried by the :authority pseudo-header (freq.Host); a
		// literal Host header beside it, or a stray Content-Length on a bodyless
		// GET, makes strict upstreams reject the request (400 Bad Request).
		if hopByHopHeaders[ln] || ln == "host" || ln == "content-length" {
			continue
		}
		for _, v := range values {
			h.Add(name, v)
		}
	}

	// Header strategy. Only impose a browser header order when the request is
	// actually a browser request; for native clients (okhttp/AppAuth/etc.)
	// forward their own headers untouched, so we don't fingerprint an okhttp
	// request as Chrome. 'browser' forces it, 'preserve' never does.
	browser := false
	switch imp.headerMode {
	case "browser":
		browser = true
	case "preserve":
		browser = false
	default: // auto
		browser = isBrowserRequest(h)
	}

	if browser {
		// A browser always sends these; fill Accept-Encoding only if absent and
		// drop the non-browser Pragma a hook may have injected.
		if h.Get("Accept-Encoding") == "" {
			h.Set("Accept-Encoding", "gzip, deflate, br")
		}
		h.Del("Pragma")
		h[fhttp.HeaderOrderKey] = chromeHeaderOrder
		h[fhttp.PHeaderOrderKey] = chromePseudoOrder
	}
	// preserve / non-browser: leave the client's headers and ordering as-is.

	freq.Header = h

	if imp.proxy != nil {
		imp.proxy.Debug("impersonate[%s] upstream %s %s | %s", imp.profileName, req.Method, req.URL.String(), headerSummary(h))
	}

	return freq, nil
}

// headerSummary renders the outgoing headers in Chrome order (then any extras)
// for -debug diffing against a known-good browser/Burp request.
func headerSummary(h fhttp.Header) string {
	var sb strings.Builder
	seen := map[string]bool{}
	emit := func(name string, vals []string) {
		for _, v := range vals {
			sb.WriteString(name)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString(" | ")
		}
	}
	for _, k := range chromeHeaderOrder {
		for name, vals := range h {
			if strings.ToLower(name) == k {
				emit(name, vals)
				seen[strings.ToLower(name)] = true
			}
		}
	}
	for name, vals := range h {
		if name == fhttp.HeaderOrderKey || name == fhttp.PHeaderOrderKey {
			continue
		}
		if !seen[strings.ToLower(name)] {
			emit(name+"(unordered)", vals)
		}
	}
	return sb.String()
}

// adaptResponse converts an fhttp.Response into a stdlib *http.Response,
// normalising it for the HTTP/1.1 client leg and optionally decompressing.
func (imp *Impersonator) adaptResponse(req *http.Request, fres *fhttp.Response) (*http.Response, error) {
	resp := &http.Response{
		StatusCode: fres.StatusCode,
		Status:     fres.Status,
		// Client leg to the MITM'd app is always HTTP/1.1 (goproxy parses the
		// client request with an HTTP/1 reader), so normalise here.
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Request:    req,
	}

	for name, values := range fres.Header {
		if hopByHopHeaders[strings.ToLower(name)] {
			continue
		}
		for _, v := range values {
			resp.Header.Add(name, v)
		}
	}

	resp.Header.Del("Transfer-Encoding")

	// decode=false: pass the body through untouched (still compressed).
	if !imp.decode {
		resp.ContentLength = fres.ContentLength
		resp.Body = fres.Body
		return resp, nil
	}

	// decode=true: buffer the body and hand the client identity-encoded bytes,
	// so SSL-strip / JS injection / logging and strict clients (AppAuth okhttp)
	// all work. tls-client's transport may or may not have already
	// decompressed; try per Content-Encoding and, on failure, assume it was
	// already identity. Either way strip Content-Encoding so the client does
	// not try to decode a second time (the cause of the gunzip EOFException).
	raw, err := io.ReadAll(fres.Body)
	_ = fres.Body.Close()
	if err != nil {
		return nil, err
	}

	out := raw
	switch strings.ToLower(strings.TrimSpace(fres.Header.Get("Content-Encoding"))) {
	case "gzip":
		if dec, derr := gunzipAll(raw); derr == nil {
			out = dec
		}
	case "deflate":
		if dec, derr := inflateAll(raw); derr == nil {
			out = dec
		}
	case "br":
		if dec, derr := io.ReadAll(brotli.NewReader(bytes.NewReader(raw))); derr == nil {
			out = dec
		}
	}

	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	resp.ContentLength = int64(len(out))
	resp.Body = io.NopCloser(bytes.NewReader(out))
	return resp, nil
}

func gunzipAll(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func inflateAll(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer r.Close()
	return io.ReadAll(r)
}
