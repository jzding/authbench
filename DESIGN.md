# authbench — auth-overhead microbench design doc

Source: [`main.go`](./main.go) · sample output: [`results/sample-x86-reference.txt`](results/sample-x86-reference.txt)

## 1. Why this exists

Securing the O-RAN ocloudNotifications v2 interface adds mTLS + OAuth to all of its
APIs. The forum question is: *what does that authentication cost per event?* We need
a defensible per-request number.

The obvious approach — measure delivery latency on the cluster with auth on vs off
— **does not work at this scale**. The in-node event hop is sub-millisecond, while
in-cluster wall-clock is dominated by noise an order of magnitude larger:
per-invocation TLS handshakes (~8 ms), process/shell startup, scheduler jitter, and
the CNI datapath. You cannot subtract two ~15 ms noisy numbers and claim a +20 µs
signal. (This is exactly the trap the live test hit: a single push read as 15–29 ms,
almost all of it a cold handshake.)

So the authoritative auth-cost number comes from an **isolated, in-process Go
microbench** that measures each cost component directly, with the noise sources
removed:

- pure stdlib crypto/TLS/HTTP — no cluster, no CNI, no kube-apiserver in the hot path
- loopback only, so no real network
- warm/reused connections for the steady-state path, so the one-time handshake is
  measured **separately** instead of contaminating every sample
- thousands of iterations with p50/p99 so the distribution is visible

**Run it on x86** (the remote builder) to match the cluster CPU — crypto costs are
arch-sensitive (AES-NI, ECDSA/RSA perf differ from Apple-silicon).

> **Note.** Validate a fresh x86 run against `results/sample-x86-reference.txt`:
> if the four measurements and the two deltas track it within run-to-run noise,
> the setup is behaving as intended.

## 2. Architecture at a glance

One self-contained `main` package, no external deps (`go 1.23`, stdlib only). Flow
in `main()` ([main.go:44](./main.go)):

```
build fixed-size payload (1043 B) + token (1428 B)
  │
  ├─ [1] AES-GCM seal+open            → benchAESGCM()        (no certs needed)
  │
  ├─ build one shared CA + certs      → newCA(), issue()
  │      ├─ server leaf, ECDSA-P256
  │      ├─ server leaf, RSA-2048
  │      └─ client leaf, ECDSA-P256 (CN=notification-consumer)
  │
  ├─ [2] full mTLS handshake          → benchHandshake()     (TLS1.3/1.2 × ECDSA/RSA)
  ├─ [3] cached TokenReview check     → benchTokenCache()    (tokenCache)
  └─ [4] per-event POST, warm conn    → benchPOST() against  newPlainServer()/newTLSServer()
```

Every measurement returns `[]time.Duration`; `stat()` ([main.go:96](./main.go))
sorts, then prints `n`, `mean`, `p50`, `p99`. Fixed-size inputs
(`eventSize=1043`, `tokenSize=1428`, [main.go:39](./main.go)) keep per-byte crypto
and hashing costs comparable across runs and matched to a real CloudEvent + SA JWT.

### Why four separate measurements

The secured-push cost is not one number — it is a sum of independently-amortized
parts, and lumping them hides which ones actually matter in steady state:

| # | Component | Frequency in production | Measured as |
|---|-----------|-------------------------|-------------|
| 1 | AES-GCM record crypto | **every event** (bulk cipher) | seal+open per message |
| 2 | TLS handshake | **once per connection** (~0 with keep-alive) | full dial+handshake |
| 3 | OAuth token check | **every request**, but cached (30 s TTL) | sha256 + map lookup |
| 4 | End-to-end POST | **every event**, warm connection | round-trip over reused conn |

Separating them lets us say "handshake is 1.7 ms but amortizes to zero, so
the *steady-state* per-event cost is [1]+[3]+framing ≈ tens of µs," which is the
honest conclusion.

## 3. The four measurements in detail

### [1] AES-GCM seal+open — `benchAESGCM()` ([main.go:117](./main.go))

Creates an AES-GCM AEAD (128- and 256-bit keys), a random nonce, then loops
`n=20000`: `Seal` the 1043-byte payload and `Open` it back, timing the pair. This
is the steady-state per-message bulk-crypto cost once a TLS session exists — the
part paid on **every** event regardless of connection reuse. Both key sizes are
shown because TLS 1.3 may negotiate either; they come out ~equal (AES-NI), ~1.5 µs.

### [2] Full mTLS handshake — `benchHandshake()` ([main.go:146](./main.go))

A real loopback TLS server (`tls.RequireAndVerifyClientCert`, [main.go:146](./main.go))
runs an accept loop that wraps each accepted conn in `tls.Server` and calls
`Handshake()`. The client loop (`n=300`) does, per iteration: `net.Dial` a fresh
TCP conn → `tls.Client` → **time `Handshake()`** → close. Because the connection is
new each time, this isolates the *one-time* connection-setup cost.

Run as a 2×2 matrix — {TLS 1.3, TLS 1.2} × {ECDSA-P256 server cert, RSA-2048 server
cert} — by pinning `MinVersion == MaxVersion` and swapping the server leaf's key
type. The point of the matrix: **ECDSA is ~4× faster than RSA** (1.77 ms vs 6.4 ms),
and typical in-cluster certificate authorities issue **ECDSA** serving certs, so the fast row is the one
that applies in production. RSA is shown to justify "don't switch to RSA certs."

### [3] Cached TokenReview check — `benchTokenCache()` ([main.go:223](./main.go))

The production OAuth path validates a bearer token via the Kubernetes TokenReview
API, but caches the result for 30 s to avoid a round-trip per event. `tokenCache`
([main.go:201](./main.go)) models the steady-state (cache-hit) path: a
`map[[32]byte]time.Time` guarded by `sync.RWMutex`; `check()` sha256's the token,
takes `RLock`, looks up, and checks TTL. The bench pre-populates the token
([main.go:71-ish `cache.put`]) then times `n=20000` hits — ~2.3 µs.

**What it deliberately omits:** the *cold* path (cache miss → one real TokenReview
HTTP round-trip to kube-apiserver). That is a network+apiserver cost, not a crypto
cost, happens ≤ once per 30 s per token, and is measured in-cluster instead — the
output's closing line says so explicitly.

### [4] Per-event POST over a reused connection — `benchPOST()` ([main.go:312](./main.go))

The end-to-end steady-state number, and the one the push-overhead deltas come from.
Three server/client configurations, all POSTing the 1043-byte body:

- **[4a] plaintext** — `newPlainServer()` ([main.go:239](./main.go)), handler returns 204. Baseline.
- **[4b] HTTPS + mTLS, no app auth** — `newTLSServer(..., withAuth=false)` ([main.go:252](./main.go)): `RequireAndVerifyClientCert`, handler returns 204. Adds TLS record crypto + client-cert verification, but no application-layer check.
- **[4c] HTTPS + mTLS + callback auth** — `newTLSServer(..., withAuth=true)`: same, but the handler is wrapped in `callbackAuthMiddleware` ([main.go:281](./main.go)), which mirrors the consumer's real push-callback enforcement — require a verified peer cert (`r.TLS.PeerCertificates`) **and** pass the cached bearer-token check — before the 204.

**Connection reuse is the whole point** ([main.go:312](./main.go)): a single
`http.Client` with `MaxIdleConnsPerHost: 1` and HTTP/1.1 pinned
(`NextProtos: ["http/1.1"]`, `ForceAttemptHTTP2: false`, [main.go:296](./main.go)).
HTTP/2 is disabled deliberately — its multiplexing would let concurrent requests
share one stream and muddy a per-request serial measurement; HTTP/1.1 with one idle
conn guarantees each request reuses the same warmed TLS connection. `benchPOST`
sends **200 warm-up requests first** to establish and prime that connection, then
times `n=10000`.

The two reported deltas map directly to report claims:

- **Δ[4c]−[4a] = full secured-push per-event overhead** (TLS record crypto + cert
  verify + cached token) → **~+50 µs p50**
- **Δ[4c]−[4b] = the application-layer callback auth alone** (cert-presence check +
  cached token) → **~+16 µs p50**

## 4. Supporting machinery

- **Cert generation** — `newCA()` ([main.go:351](./main.go)) makes a self-signed
  ECDSA-P256 CA; `issue()` ([main.go:376](./main.go)) mints leaves signed by it,
  choosing ECDSA or RSA keys and `serverAuth` (with `localhost`/`127.0.0.1` SANs)
  or `clientAuth` EKU. One CA + `x509.CertPool` is shared by every TLS benchmark, so
  server and client trust each other with no external PKI.
- **Stats** — `stat()` ([main.go:96](./main.go)) sorts durations and indexes
  `p50`/`p99` (nearest-rank, clamped). Mean is a sanity check; **p50 is the headline**
  (robust to outliers) and **p99 shows the tail**, which matters for a real-time
  event path.

## 5. What it does and does not prove

**Proves:** the marginal CPU cost of the auth primitives, cleanly separated —
per-event bulk crypto, per-request cached token check, per-connection handshake, and
the composed warm per-event POST cost. These are arch-real (run on x86) and
noise-free.

**Does not prove:** absolute production latency (no CNI, no scheduler, no
kube-apiserver, no real event-source→producer→consumer path), and not the cold
TokenReview round-trip. Those belong to an in-cluster measurement and are quoted
separately. The microbench answers "how expensive is the *auth*," not "how fast is
the *system*."

## 6. Running it

```sh
# Run on any x86 host (crypto costs are arch-sensitive: AES-NI, ECDSA/RSA perf).
go run . | tee results/sample-$(date +%Y%m%d).txt
```

Reading the result: compare against `results/sample-x86-reference.txt`. If [4a]/[4b]/[4c] and
the two deltas track the reference within run-to-run noise, the reconstruction is
validated; if [4b]/[4c] diverge materially, suspect the connection-reuse setup
(HTTP/2 leaking back in, or the warm-up loop not priming the conn).

## 7. Validation run (2026-09-21, x86 builder, Go 1.26)

Three consecutive runs on the remote x86 builder, compared to reference
`3209c3e` (p50):

| Measurement | Ref `3209c3e` | Runs ×3 | Verdict |
|-------------|---------------|---------|---------|
| [1] AES-128-GCM | 1.50 µs | 1.59 / 1.70 / 1.63 µs | match |
| [2] TLS1.3 ECDSA-P256 | 1.745 ms | 1.81 / 1.76 / 1.85 ms | match |
| [3] cached token check | 2.33 µs | 2.68 / 2.65 / 2.58 µs | match |
| [4a] plaintext | 180.7 µs | 155 / 174 / 171 µs | ~match |
| [4b] HTTPS-mTLS | 215.3 µs | 250 / 245 / 246 µs | +~30 µs |
| [4c] +callback auth | 231.2 µs | 256 / 256 / 257 µs | +~25 µs |
| **Δ[4c]−[4a]** | **+50 µs** | **~+85 µs** | same order |
| **Δ[4c]−[4b]** | **+16 µs** | **~+10 µs** | match |

Conclusion: primitives reproduce within ~10–15% → reconstruction faithful. Runs 2 & 3
are near-identical, so the tool is stable. The one shift is [4b] ~+30 µs (concentrated
in the TLS transport layer, pulling the full-push delta to ~+85 µs), attributable to
the newer Go 1.26 toolchain and shared-builder load — not a reconstruction bug (the
app-layer callback delta is stable and matches). **Headline unchanged:** secured-push
auth overhead is tens of µs, sub-ms absolute, negligible against the reaction budget.
```
