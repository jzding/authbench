// authbench — auth-overhead microbench for the O-RAN ocloudNotifications v2
// interface (secured PUSH callback: mTLS + OAuth).
//
// Pure Go stdlib, no cluster needed. Run on x86 to match a typical cluster
// arch. Measures the four
// per-request auth costs:
//
//	[1] AES-GCM seal+open per event   (steady-state per-message crypto)
//	[2] Full mTLS handshake           (one-time per connection; ~0 with keep-alive)
//	[3] Cached TokenReview check       (sha256 + mutex map lookup)
//	[4] Per-event POST over a REUSED connection: [4a] plaintext /
//	    [4b] HTTPS-mTLS no handler auth / [4c] HTTPS-mTLS + callbackAuthMiddleware
package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	eventSize = 1043 // bytes — matches the 1043-byte CloudEvent payload
	tokenSize = 1428 // bytes — matches the 1428-byte bearer token
)

func main() {
	payload := bytes.Repeat([]byte("x"), eventSize)
	token := strings.Repeat("t", tokenSize)

	fmt.Println("=== authbench: O-RAN ocloudNotifications v2 auth-overhead microbench (secured PUSH callback) ===")
	fmt.Printf("event payload size: %d bytes; bearer token size: %d bytes\n\n", eventSize, tokenSize)

	// ---- [1] AES-GCM seal+open per event ---------------------------------
	fmt.Println("[1] AES-GCM seal+open per event (steady-state per-message crypto cost):")
	stat("AES-128-GCM", benchAESGCM(16, 20000, payload))
	stat("AES-256-GCM", benchAESGCM(32, 20000, payload))
	fmt.Println()

	// Shared CA + certs for the TLS benchmarks.
	caCert, caKey := newCA()
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	srvECDSA := issue(caCert, caKey, "localhost", true, false)
	srvRSA := issue(caCert, caKey, "localhost", true, true)
	cliCert := issue(caCert, caKey, "notification-consumer", false, false)

	// ---- [2] Full mTLS handshake -----------------------------------------
	fmt.Println("[2] Full mTLS handshake (one-time per connection; ~0 with keep-alive):")
	stat("TLS1.3 ECDSA-P256", benchHandshake(tls.VersionTLS13, srvECDSA, cliCert, pool, 300))
	stat("TLS1.3 RSA-2048", benchHandshake(tls.VersionTLS13, srvRSA, cliCert, pool, 300))
	stat("TLS1.2 ECDSA-P256", benchHandshake(tls.VersionTLS12, srvECDSA, cliCert, pool, 300))
	stat("TLS1.2 RSA-2048", benchHandshake(tls.VersionTLS12, srvRSA, cliCert, pool, 300))
	fmt.Println()

	// ---- [3] Cached TokenReview check ------------------------------------
	fmt.Println("[3] Cached TokenReview check per request (sha256 + mutex map lookup):")
	cache := newTokenCache()
	cache.put(token, 30*time.Second) // warm hit (steady state, <=1 miss / 30s)
	stat("token cache hit", benchTokenCache(cache, token, 20000))
	fmt.Println()

	// ---- [4] Per-event POST over a REUSED connection ---------------------
	fmt.Println("[4] Per-event POST over a REUSED connection (warm):")
	stat("[4a] plaintext HTTP push (both modes pre-fix)", benchPOST(newPlainServer(), nil, payload, "", 10000))
	stat("[4b] HTTPS mTLS push, no handler auth", benchPOST(newTLSServer(srvECDSA, pool, false, cache), tlsClient(cliCert, pool), payload, token, 10000))
	stat("[4c] HTTPS mTLS push + callbackAuthMiddleware", benchPOST(newTLSServer(srvECDSA, pool, true, cache), tlsClient(cliCert, pool), payload, token, 10000))
	fmt.Println()

	fmt.Println("Δ [4c]-[4a] = full secured-push per-event overhead (TLS + client-cert verify + cached token).")
	fmt.Println("Δ [4c]-[4b] = added cost of the callbackAuthMiddleware over plain HTTPS-mTLS.")
	fmt.Println("Cold path (cache miss, <=1x per 30s): one Kubernetes TokenReview API round-trip; measured in-cluster.")
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

func stat(name string, ds []time.Duration) {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	pct := func(q float64) time.Duration {
		i := int(float64(len(ds)) * q)
		if i >= len(ds) {
			i = len(ds) - 1
		}
		return ds[i]
	}
	fmt.Printf("  %-44s n=%d  mean=%v  p50=%v  p99=%v\n",
		name, len(ds), sum/time.Duration(len(ds)), pct(0.50), pct(0.99))
}

// ---------------------------------------------------------------------------
// [1] AES-GCM
// ---------------------------------------------------------------------------

func benchAESGCM(keyLen, n int, payload []byte) []time.Duration {
	key := make([]byte, keyLen)
	rand.Read(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ds := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		t := time.Now()
		ct := gcm.Seal(nil, nonce, payload, nil)
		if _, err := gcm.Open(nil, nonce, ct, nil); err != nil {
			panic(err)
		}
		ds[i] = time.Since(t)
	}
	return ds
}

// ---------------------------------------------------------------------------
// [2] mTLS handshake
// ---------------------------------------------------------------------------

func benchHandshake(ver uint16, serverCert, clientCert tls.Certificate, pool *x509.CertPool, n int) []time.Duration {
	srvCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   ver,
		MaxVersion:   ver,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				tc := tls.Server(c, srvCfg)
				_ = tc.Handshake()
				tc.Close()
			}(c)
		}
	}()

	cliCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
		ServerName:   "localhost",
		MinVersion:   ver,
		MaxVersion:   ver,
	}
	ds := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			panic(err)
		}
		tc := tls.Client(raw, cliCfg)
		t := time.Now()
		if err := tc.Handshake(); err != nil {
			panic(err)
		}
		ds[i] = time.Since(t)
		tc.Close()
	}
	return ds
}

// ---------------------------------------------------------------------------
// [3] cached token check
// ---------------------------------------------------------------------------

type tokenCache struct {
	mu sync.RWMutex
	m  map[[32]byte]time.Time
}

func newTokenCache() *tokenCache { return &tokenCache{m: make(map[[32]byte]time.Time)} }

func (c *tokenCache) put(tok string, ttl time.Duration) {
	h := sha256.Sum256([]byte(tok))
	c.mu.Lock()
	c.m[h] = time.Now().Add(ttl)
	c.mu.Unlock()
}

func (c *tokenCache) check(tok string) bool {
	h := sha256.Sum256([]byte(tok))
	c.mu.RLock()
	exp, ok := c.m[h]
	c.mu.RUnlock()
	return ok && time.Now().Before(exp)
}

func benchTokenCache(c *tokenCache, token string, n int) []time.Duration {
	ds := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		t := time.Now()
		if !c.check(token) {
			panic("expected cache hit")
		}
		ds[i] = time.Since(t)
	}
	return ds
}

// ---------------------------------------------------------------------------
// [4] POST over reused connection
// ---------------------------------------------------------------------------

func newPlainServer() string {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go (&http.Server{Handler: h}).Serve(ln)
	return "http://" + ln.Addr().String() + "/event"
}

func newTLSServer(serverCert tls.Certificate, pool *x509.CertPool, withAuth bool, cache *tokenCache) string {
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
	if withAuth {
		h = callbackAuthMiddleware(cache, h)
	}
	srv := &http.Server{
		Handler: h,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"http/1.1"}, // pin HTTP/1.1 so one conn is reused
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go srv.ServeTLS(ln, "", "")
	return "https://" + ln.Addr().String() + "/event"
}

// callbackAuthMiddleware mirrors the consumer's push-callback enforcement:
// client cert must be present+verified (mTLS already did the verify) AND the
// bearer token must pass the cached TokenReview check.
func callbackAuthMiddleware(cache *tokenCache, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !cache.check(tok) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func tlsClient(clientCert tls.Certificate, pool *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   false,
			MaxIdleConnsPerHost: 1,
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      pool,
				ServerName:   "localhost",
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"http/1.1"},
			},
		},
	}
}

func benchPOST(url string, client *http.Client, payload []byte, token string, n int) []time.Duration {
	if client == nil {
		client = &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 1}}
	}
	do := func() {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			panic(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			panic(fmt.Sprintf("unexpected status %d", resp.StatusCode))
		}
	}
	for i := 0; i < 200; i++ { // warm: establish + reuse the connection
		do()
	}
	ds := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		t := time.Now()
		do()
		ds[i] = time.Since(t)
	}
	return ds
}

// ---------------------------------------------------------------------------
// cert helpers
// ---------------------------------------------------------------------------

func newCA() (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bench-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert, key
}

func issue(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, server, rsaKey bool) tls.Certificate {
	var pub crypto.PublicKey
	var priv crypto.PrivateKey
	if rsaKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		pub, priv = &k.PublicKey, k
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		pub, priv = &k.PublicKey, k
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		panic(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caCert.Raw}, PrivateKey: priv, Leaf: leaf}
}
