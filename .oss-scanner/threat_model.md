# ckpool threat model

## Project and scope

ckpool is a Linux Bitcoin mining pool and proxy written primarily in C, with a
C++ adapter for Bitcoin Core's Cap'n Proto mining IPC interface. It handles
Stratum V1 (SV1), Stratum V2 (SV2), SV2 Job Declaration, share accounting, block
construction/submission, and proxying to upstream pools. Review the `master`
branch, including optional SV2 and IPC code enabled in this image.

The main executable is `/src/src/ckpool`. Proxy, passthrough, redirector and
trusted-node modes share its implementation; consult `README-CKPOOL_MODES.md`,
`README-CKPROXY.md` and `README.md` for configuration and protocol entry points.
Do not assume that successful setup, a Noise handshake or an accepted share
makes a miner trustworthy. Worker names, payout addresses and suggested
difficulties remain attacker-controlled throughout a connection's lifetime.

## Assets and trust boundaries

- Availability of the pool, its event workers, job generation and block
  submission. One client's traffic must not crash the process, deadlock workers
  or exhaust resources shared by other miners.
- Integrity of share validation and accounting, difficulty/target calculations,
  job and channel ownership, extranonce allocation, and block reward outputs.
  A miner must not obtain another miner's credit or redirect a coinbase payout.
- Isolation of connections, channels and Job Declaration sessions. Requests,
  tokens, jobs and replies must remain bound to the proper owner and lifetime,
  including after reconnects and numeric identifier reuse.
- Confidentiality and integrity of SV2 authority/static private keys, upstream
  credentials, node RPC credentials and other process memory. Key files and
  configuration are supplied by the operator, not by miners.

Internet-facing SV1, SV2 mining and SV2 Job Declaration listeners receive
untrusted input. An attacker may open many connections, complete handshakes,
open multiple channels, pipeline or fragment requests, disconnect at any point,
and send malformed or semantically inconsistent messages. Include slow peers,
partial writes, stalled readers, replayed messages and reconnect churn.

A configured upstream SV1/SV2 pool or Job Declaration Server can also send
hostile responses to ckproxy. SV2 authority verification authenticates that
endpoint; it does not make its message contents or accounting trustworthy.
Consider loss/re-establishment of either upstream connection independently.

Bitcoin Core RPC, mining IPC sockets, ZMQ notifications, trusted-node listeners
and local control sockets belong to explicitly configured trust relationships.
Identify the required access or configuration when reporting issues on those
paths. They are not all public unauthenticated endpoints. Still examine parser
bounds, error handling, and remote miner requests that trigger node operations.
Configuration files, command-line options and executable replacement are trusted
operator inputs; an attacker already able to replace these is not the primary
threat. A remote path reaching an unsafe local operation remains in scope.

## Components and priorities

1. `src/connector.c`, `src/sv2_conn.c`, `src/sv2_noise.c`: connection and worker
   lifetimes, buffered I/O, frame lengths, handshake admission and expiry,
   certificate verification, key/nonce handling, locking and disconnect cleanup.
2. `src/sv2_codec.c`, `src/sv2_tx.c`, `src/sv2_cb.c`: length/count arithmetic,
   truncated and oversized input, string termination and embedded NULs,
   transaction parsing, coinbase assembly, allocation limits and parser progress.
3. `src/stratifier.c`, `src/sv2_strat.c`, `src/sv2_bridge.c`: SV1 and SV2
   identity validation, channel/group assignment, job lifetimes, share validation,
   target/difficulty conversion, integer/floating-point edge cases, and accounting
   for accepted, rejected, stale and duplicate shares. Pay particular attention
   to attacker-selected difficulties before and after any accepted shares.
4. `src/sv2_jd.c`: token/session binding, transaction identification and retrieval,
   declarations, candidate-block validation and custom-job activation. Check
   payout enforcement, stale jobs, transaction snapshot retention, quotas and
   expensive validation work that a client can repeatedly request.
5. `src/sv2_jdc.c`, `src/generator.c`, `src/bitcoin.c`: malicious upstream
   responses, correlation of requests/jobs across reconnects, proxy share
   translation, template data and block submission. Mining and declaration
   connections must not confuse one another's session state.
6. `ipc/mining/mining_ipc.cpp`, `src/libckpool.c`, `src/yyjson_util.c` and other
   shared helpers: cross-thread ownership, task queues, C/C++ boundaries, timeouts,
   serialization, address handling and unchecked size conversions. Review callers
   of bundled parsers and cryptographic libraries as part of these boundaries.

The bundled `src/secp256k1` submodule and `src/yyjson.c` are dependencies. Focus
on ckpool's integration and reachable impact; identify the upstream component
and version if a finding originates there. Bitcoin consensus validation is
delegated to Bitcoin Core where required: distinguish a bypass in ckpool from
a claim that requires a compromised node. This checkout does not include a
ckp2p implementation; do not base findings on unrelated branches or local files.

## Building and exercising the code

The enrollment Dockerfile builds in `/src` with SV2, ZMQ and Cap'n Proto IPC,
debug information and frame pointers. It fetches the pinned secp256k1 submodule
and compiles the checked-in IPC C++ bindings. The vendored `.capnp` files are
incomplete; do not regenerate bindings from that subset. The compiler and all
dependencies remain installed. No Bitcoin node, credentials, production keys or
blockchain download is needed for the bundled test suite.

From `/src`, with network access disabled:

```sh
make -j 32
make -j 32 check
cat test/test-suite.log
SV2_FUZZ_ITERS=100000 ./test/sv2_codec_fuzz
```

`make check` currently runs 16 tests: hashing, address validation with an RPC
stub, reject accounting, SV2 codecs and mutation fuzzing, authority-key encoding,
Noise handshakes, handshake limits, idle expiry, transactions, coinbase assembly,
SV1/SV2 bridging, channel groups/identities, JD snapshot retention, proxy jobs,
and JDC session handling. Tests are under `test/`, with standalone binaries next
to their C sources. Failures are recorded in `test/*.log` and
`test/test-suite.log`. The mutation driver is a bounded regression exerciser,
not a substitute for sustained coverage-guided fuzzing.

Several tests include implementation files and stub other subsystems. They are
useful starting points for isolated reproducers, but passing them does not prove
end-to-end network behavior or a working live Bitcoin Core IPC connection.
There is no live Bitcoin node in this image. Full protocol tests needing one
must use a local regtest node or a local stub, and must describe that additional
setup. Do not attempt production-node or production-pool connections.

For a clean rebuild or sanitizer experiment, preserve the generated IPC sources,
run `make clean`, reconfigure with explicit `CFLAGS`, `CXXFLAGS` and `LDFLAGS`,
then run `make -j 32 check`. The separately configured secp256k1 submodule needs
its own clean/reconfiguration if instrumenting that library. Sanitizer findings
should identify whether the fault is reachable through ckpool's real inputs.
`configure` selects hashing CPU instructions from the build machine; reconfigure
and rebuild if moving the development image to an incompatible CPU.

For local image verification, use a fresh clone as the build context, adding the
enrollment files if they are not yet committed. Do not copy a live working tree
with pool configurations, logs, core dumps or private keys into the image:

```sh
podman build -t ckpool-oss-scanner -f .oss-scanner/Dockerfile .
podman run --rm --network none -w /src ckpool-oss-scanner make -j 32 check
```

Docker accepts the same build/run arguments. The scanner's `project.yaml` is
kept in `.oss-scanner/enrollment/` so it can reference the Dockerfile and threat
model in this repository without supplying duplicate adjacent copies. Copy that
YAML alone to `projects/ckpool/project.yaml` in the scanner enrollment repository
after the referenced files are available on ckpool's public `master` branch.

## Impact and reporting

Prioritize reproducible remotely reachable memory corruption, arbitrary code
execution, secret disclosure, cross-client state corruption and payout or share
validation bypasses. Unauthenticated repeatable process termination, especially
by an automatically reconnecting client, is a significant availability issue.
Resource findings should demonstrate attacker cost, retained memory/CPU/queue
growth, relevant configured limits and whether resources are released. Ordinary
work proportional to valid mining traffic is not by itself a vulnerability.

Give the exact commit, build options, mode and configuration prerequisites,
minimal input/reproducer, observed impact and relevant stack trace or sanitizer
output. Separate a proven network exploit from an isolated helper failure or a
specification mismatch with no demonstrated security consequence. Assess severity
from reachability and impact rather than assigning every crash the same rating.

Follow `README-SECURITY.md`: report privately to Con Kolivas at
`kernel@kolivas.org`. Perform experiments only against disposable local test
instances, using generated test keys and synthetic credentials.
