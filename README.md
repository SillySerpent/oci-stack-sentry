# OCI Stack Sentry

Capacity-aware Cloudflare Worker for Oracle OCI Resource Manager stack automation.

OCI Stack Sentry watches Oracle Resource Manager stack activity, applies smart retry rules, optionally checks compute capacity before launching a new apply job, and can notify you when something important happens.

## Why use it

Provisioning Always Free compute in busy regions can be inconsistent. Blind retries often waste API calls and make it harder to tell what is actually happening. This project aims to make the process more deliberate:

- checks for active stack jobs before submitting another run
- enforces cooldown windows between attempts
- optionally gates apply requests behind a compute capacity check
- persists backoff state with Workers KV
- adds retry tokens to create-style requests
- supports Discord notifications and manual trigger endpoints

## Core features

- **Scheduled execution** with Cloudflare Cron Triggers
- **Manual trigger endpoint** for testing or forced runs
- **Capacity-aware mode** for shape and placement checks before apply
- **Persisted backoff** so rate-limit handling survives between runs
- **Notification hooks** for success, failure windows, and manual tests
- **Workers KV support** for shared state across cron invocations

## How it works

On each run the worker follows this general flow:

1. Read current state from KV if configured.
2. Check whether an apply job is already active.
3. Respect cooldown and temporary backoff windows.
4. Optionally call the compute capacity report flow.
5. Submit a new Resource Manager apply job only when conditions allow it.
6. Persist updated state and emit notifications when configured.

## Endpoints

- `GET /` — basic health and runtime info
- `POST /run` — manual run
- `POST /run?force=1` — bypass cooldown once
- `POST /run?test_discord=1` — send a Discord test notification
- `GET /state` — inspect persisted state

If `MANUAL_RUN_TOKEN` is set, send it in the `x-run-token` header for manual routes.

## Project structure

```text
.
├── src/
│   ├── lib.rs              # Worker logic and request flow
│   └── crypto_bridge.js    # WebCrypto bridge for OCI request signing
├── Cargo.toml
├── package.json
├── wrangler.toml
└── .dev.vars.example
```

## Environment variables

### Required

- `OCI_TENANCY_OCID`
- `OCI_USER_OCID`
- `OCI_FINGERPRINT`
- `OCI_REGION`
- `OCI_STACK_OCID`
- `OCI_PRIVATE_KEY_PEM`

### Optional capacity-aware settings

- `ENABLE_CAPACITY_GATE=true`
- `OCI_COMPARTMENT_OCID`
- `OCI_AVAILABILITY_DOMAIN`
- `OCI_INSTANCE_SHAPE`
- `OCI_FAULT_DOMAIN`
- `OCI_SHAPE_OCPUS`
- `OCI_SHAPE_MEMORY_GBS`
- `OCI_SHAPE_BASELINE_OCPU_UTILIZATION`

### Optional control and notification settings

- `DISCORD_WEBHOOK_URL`
- `MANUAL_RUN_TOKEN`
- `COOLDOWN_MINUTES`
- `FAILURE_ALERT_WINDOW_HOURS`
- `SUCCESS_NOTIFY_LOOKBACK_MINUTES`
- `FAILURE_NOTIFY_LOOKBACK_MINUTES`

## Deploying to Cloudflare

### Option 1: GitHub import in the Cloudflare dashboard

This is the easiest path if you do not want to deploy from your own terminal.

1. Push this repository to GitHub.
2. In Cloudflare, create a Worker by importing the GitHub repository.
3. Use the repository root as the project root.
4. Set the build command to:

```bash
cargo install -q worker-build && worker-build --release
```

5. Set the deploy command to:

```bash
npx wrangler deploy
```

6. Add your runtime secrets in **Settings → Variables & Secrets**.
7. Create and bind a KV namespace if you want persisted state.

### Option 2: Wrangler

```bash
npm install
npx wrangler deploy
```

## KV setup

If you want persisted state, create a KV namespace and add it to `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "STATE_KV"
id = "YOUR_PRODUCTION_NAMESPACE_ID"
preview_id = "YOUR_PREVIEW_NAMESPACE_ID"
```

## Recommended first checks after deploy

1. Open `/` and confirm the worker responds.
2. Call `POST /run?test_discord=1` if notifications are enabled.
3. Call `POST /run?force=1` with your manual token to verify the Oracle path.
4. Use Cloudflare logs or `wrangler tail` to inspect behavior.
5. Confirm cron runs after trigger propagation.

## Notes

- This project is intended for Cloudflare Workers and Rust-based Worker builds.
- Capacity-aware mode is only as good as the placement information you provide.
- Busy OCI regions can still remain unavailable for extended periods.
- Protect manual and state endpoints before exposing them broadly.

## License

MIT
