# authbench

A small, **platform-neutral microbenchmark** of the per-event CPU cost of adding
**mutual TLS + OAuth** to the O-RAN *ocloudNotifications v2* notification interface
(the secured event-**push** callback in particular).

It answers one question: *what does authenticating each notification actually
cost?* — and it answers it cleanly, by measuring the **security mechanisms
themselves** rather than a whole cluster.

## Why a microbenchmark

Measuring auth overhead on a live cluster does not work at this scale. The in-node
event hop is sub-millisecond, but end-to-end wall-clock is dominated by noise an
order of magnitude larger — per-connection TLS handshakes (~ms), process startup,
scheduler jitter, and the CNI datapath. You cannot subtract two ~15 ms noisy
numbers and claim a +20 µs signal.

So this tool isolates each cost component **in-process**, with the noise removed:

- pure Go **standard library** crypto / TLS / HTTP — no cluster, no CNI, no
  kube-apiserver in the hot path;
- **loopback only**, so no real network;
- **warm / reused** connections for the steady-state path, so the one-time
  handshake is measured *separately* instead of contaminating every sample;
- thousands of iterations with **p50 / p99** so the distribution is visible.

Because it is nothing but stdlib TLS 1.3 / ECDSA P-256 / AES-GCM and a cached
token check, the numbers reflect the **security approach**, not any vendor or
platform — any conformant implementation pays a similar cost.

## What it measures

| # | Component | Frequency in production | Measured as |
|---|-----------|-------------------------|-------------|
| 1 | AES-GCM record crypto | every event (bulk cipher) | seal+open per message |
| 2 | TLS handshake | once per connection (~0 with keep-alive) | full dial+handshake, TLS 1.3/1.2 × ECDSA/RSA |
| 3 | OAuth token check | every request, but cached (30 s TTL) | sha256 + mutex-map lookup |
| 4 | End-to-end POST | every event, warm connection | round-trip over a reused conn, three variants |

The three variant [4] configurations give the headline deltas:

- **[4a]** plaintext HTTP push — baseline
- **[4b]** HTTPS + mTLS, no application auth
- **[4c]** HTTPS + mTLS + callback middleware (verified client cert **and** cached
  bearer-token check) — mirrors the real secured push callback

- **Δ [4c] − [4a]** = full secured-push per-event overhead
- **Δ [4c] − [4b]** = the application-layer callback auth alone

## Running

Requires Go (module targets `go 1.23`). Run on an **x86** host to match a typical
cluster CPU — crypto costs are architecture-sensitive (AES-NI, ECDSA/RSA
performance differ on Apple silicon).

```sh
go run . | tee results/sample-$(date +%Y%m%d).txt
```

## Sample results

`results/sample-x86-reference.txt` and `results/sample-x86-validation.txt` are two
x86 runs. Representative p50 figures (~1 KB event, warm keep-alive connection):

| Measurement | p50 |
|-------------|-----|
| [1] AES-GCM seal+open per message | ~1.5 µs |
| [2] TLS 1.3 handshake, ECDSA P-256 (one-time) | ~1.7 ms (≈ 4× faster than RSA-2048) |
| [3] cached token check | ~2.3 µs |
| [4a] plaintext push | ~181 µs |
| [4b] HTTPS-mTLS push | ~215 µs |
| [4c] HTTPS-mTLS + callback auth | ~231 µs |
| **Δ full secured push ([4c]−[4a])** | **~+50 µs** |
| **Δ app-layer auth ([4c]−[4b])** | **~+16 µs** |

**Takeaway:** the steady-state cost of authenticating each pushed event is tens of
microseconds; the handshake is milliseconds but is paid once per connection and
amortizes to ~0 with keep-alive; bulk encryption is not the cost driver.

## What it does and does not prove

**Proves:** the marginal CPU cost of the auth primitives, cleanly separated —
per-event bulk crypto, per-request cached token check, per-connection handshake,
and the composed warm per-event POST cost.

**Does not prove:** absolute production latency (no CNI, no scheduler, no
kube-apiserver, no real event-source path) and not the *cold* TokenReview
round-trip (a cache miss, ≤ once per 30 s per token). Those belong to an in-cluster
measurement. This microbench answers "how expensive is the *auth*," not "how fast
is the *system*."

## Docs

- [`DESIGN.md`](./DESIGN.md) — full design and per-measurement rationale
- [`docs/architecture.svg`](./docs/architecture.svg) — what the microbench isolates (the timed path)

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE).
