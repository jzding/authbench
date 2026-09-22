What the diagram shows

The measured path (red) — the headline latency is exactly one client.Do() round-trip over a warm, reused connection:

▎ t := time.Now() → client TLS-encrypts (AES-GCM) → POST /event across the loopback keep-alive connection → server TLS-decrypts → callbackAuthMiddleware (verify peer cert + tokenCache.check) → handler returns 204 → response back to client → ds[i] = time.Since(t)

Everything is one Go process on 127.0.0.1 — no network, CNI, or kube-apiserver in the hot path, which is the whole point (the in-cluster noise is 10× the signal).

Three things deliberately excluded from the timed span, shown as grey/side elements so the measurement is honest:
- Handshake [2] (~1.7 ms) — excluded by connection reuse (200 warm-ups prime the one conn first).
- Cert/CA setup — built once at startup, dashed grey (off the timed path).
- Token cold path (real TokenReview RTT) — excluded by the cache; measured in-cluster instead.

The bottom row makes the attribution explicit:
- [1] AES-GCM ~1.5 µs, [2] ECDSA handshake ~1.7 ms, [3] cached token ~2.3 µs — each measured in isolation.
- [4] variants are the end-to-end round-trip: [4a] plaintext 181 µs → [4b] HTTPS-mTLS 215 µs → [4c] +callback-auth 231 µs. The latency is the round-trip; the overhead is the delta between variants — Δ = +50 µs (full secured push), +16 µs (app-layer auth alone).

This matches the DESIGN.md structure.
