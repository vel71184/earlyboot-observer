Early Boot Observer watches early system readiness signals and reports via stdout for journald.

Check lifecycle
- Checks are armed once prerequisites events are emitted; unresolved armed checks fail at the runtime limit.
- Engine logs each resolution as `CHECK=<name> RESULT=<PASS|FAIL|SKIP|WARN> REASON=<text>`.
- Runtime limit defaults to 30s; per-check deadlines are bounded by this limit.

NET_READY gating
- Network readiness requires NetworkManager connectivity `full` or `limited` and either an IPv4 address or a default route on any device.
- When NET_READY flips true, the engine emits `EVENT_NET_READY` and resolves the `NET_READY` check to PASS, then starts DNS, time, and HTTP probes.
- Without NET_READY, dependent checks skip at shutdown.

Unit checks
- Monitors `NetworkManager.service`, `ssh.service`, `tailscaled.service`, and `pihole-FTL.service`.
- PASS when ActiveState becomes `active`; FAIL on `failed`; SKIP if the unit is missing.

DNS checks
- `DNS_OK_SYSTEM`: resolves `debian.org` via `getent hosts` then `socket.getaddrinfo`, up to 5 retries with 2s spacing, 2s per-attempt timeout, deadline 12s or runtime limit; PASS on first success, FAIL after retries/deadline.
- `DNS_OK_QUAD9`: manual UDP A-query for `debian.org` to `9.9.9.9:53` with the same retry cadence/deadline; requires a valid response with answers.

Time sync
- `TIME_SYNC_OK`: runs `timedatectl show -p NTPSynchronized --value` up to 3 attempts, 3s apart, 5s per attempt, deadline 10s or runtime limit; PASS on `yes`, FAIL otherwise.
- Skips immediately if GLib is unavailable (no async loop).

HTTP probes (prerequisite: NET_READY)
- `HTTP_OK_DEBIAN`: GET https://deb.debian.org, succeeds on any HTTP response.
- `HTTP_PIHOLE_API`: GET http://127.0.0.1/admin/api.php expecting JSON object containing `domains_being_blocked`.
- `HTTP_NEXTCLOUD_STATUS`: GET http://127.0.0.1/nextcloud/status.php expecting JSON `installed` true.
- `HTTP_OLLAMA_TAGS`: GET http://127.0.0.1:11434/api/tags expecting HTTP success.
- `HTTP_FASTAPI_WHISPER_DOCS`: GET http://127.0.0.1:8000/docs expecting HTTP success.
- HTTP checks skip if GLib is absent.

Summary logging
- Final line: `SUMMARY PASS=<n> FAIL=<n> SKIP=<n> WARN=<n> [FAILED=<comma-separated list>]`.
- Logs go to stdout for journald ingestion.

Exit codes
- Returns 0 when no checks failed; returns 1 if any check resolved to FAIL.
