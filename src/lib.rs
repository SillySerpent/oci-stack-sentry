use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use js_sys::{Date, JsString, Math};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;
use worker::*;

#[wasm_bindgen(module = "/src/crypto_bridge.js")]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn sha256_base64_from_bytes(bytes: Vec<u8>) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    async fn import_pkcs8_private_key(bytes: Vec<u8>) -> std::result::Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    async fn sign_string_base64(input: String, key: JsValue) -> std::result::Result<JsValue, JsValue>;
}

const STATE_KEY: &str = "oracle_vm_worker_state";

#[event(scheduled)]
async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let meta = TriggerMeta {
        trigger: "cron".to_string(),
        cron: Some(event.cron()),
        forced: false,
    };

    if let Err(err) = run_job(&env, meta).await {
        console_error!("scheduled run error: {}", err);
    }
}

#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    let path = req.path();
    let method = req.method();
    let url = req.url()?;

    if path == "/" {
        return json_response(
            json!({
                "ok": true,
                "service": "oci-stack-retry-rust",
                "message": "Rust Worker is deployed.",
                "manual_trigger": {
                    "method": "POST",
                    "path": "/run",
                    "header": "x-run-token"
                },
                "extra_routes": ["GET /state"]
            }),
            200,
        );
    }

    if path == "/state" {
        let state = load_state(&env).await.unwrap_or_default();
        return json_response(json!({"ok": true, "state": state}), 200);
    }

    if path != "/run" {
        return json_response(json!({"ok": false, "error": "Not found"}), 404);
    }

    if method != Method::Post {
        return json_response(
            json!({
                "ok": false,
                "error": "Use POST /run with x-run-token header"
            }),
            405,
        );
    }

    if let Ok(expected) = env.var("MANUAL_RUN_TOKEN") {
        let supplied = req.headers().get("x-run-token")?;
        let expected = expected.to_string();
        if supplied.as_deref() != Some(expected.as_str()) {
            return json_response(json!({"ok": false, "error": "Unauthorized"}), 401);
        }
    }

    let test_discord = url
        .query_pairs()
        .find(|(k, _)| k == "test_discord")
        .map(|(_, v)| v == "1")
        .unwrap_or(false);

    if test_discord {
        notify_discord(
            &env,
            &[
                "🧪 **Discord test notification**".to_string(),
                "Your Rust Cloudflare Worker can send Discord messages successfully.".to_string(),
                format!("Time: {}", iso_now()),
            ]
            .join("\n"),
        )
        .await;

        return json_response(json!({"ok": true, "action": "test_discord_sent"}), 200);
    }

    let forced = url
        .query_pairs()
        .find(|(k, _)| k == "force")
        .map(|(_, v)| v == "1")
        .unwrap_or(false);

    match run_job(
        &env,
        TriggerMeta {
            trigger: "manual".to_string(),
            cron: None,
            forced,
        },
    )
    .await
    {
        Ok(result) => {
            let status = if result.ok { 200 } else { 500 };
            json_response(serde_json::to_value(result).unwrap_or_else(|_| json!({"ok": false})), status)
        }
        Err(err) => json_response(
            json!({
                "ok": false,
                "stage": "fetch-handler",
                "error": err.to_string()
            }),
            500,
        ),
    }
}

async fn run_job(env: &Env, meta: TriggerMeta) -> Result<RunResult> {
    let config = Config::from_env(env)?;
    let mut state = load_state(env).await.unwrap_or_default();
    let now_ms = now_ms();

    if !meta.forced {
        if let Some(next_allowed_ms) = state.next_allowed_attempt_ms {
            if next_allowed_ms > now_ms {
                return Ok(RunResult::skipped(
                    "backoff",
                    json!({
                        "next_allowed_attempt_ms": next_allowed_ms,
                        "trigger": meta.trigger,
                        "cron": meta.cron
                    }),
                ));
            }
        }
    }

    console_log!(
        "[{}] starting run trigger={} forced={} cron={:?}",
        iso_now(),
        meta.trigger,
        meta.forced,
        meta.cron
    );

    let imported_key = import_signing_key(&config.private_key_pem).await?;
    let oracle = OracleClient::new(config.clone(), imported_key);

    let jobs_outcome = oracle.list_jobs().await?;
    if jobs_outcome.status == 429 {
        let backoff_ms = compute_backoff_ms(&jobs_outcome.retry_after, state.rate_limit_strikes);
        state.rate_limit_strikes += 1;
        state.next_allowed_attempt_ms = Some(now_ms + backoff_ms);
        save_state(env, &state).await;

        return Ok(RunResult::backoff(
            "list-jobs",
            jobs_outcome.status,
            jobs_outcome.retry_after,
            jobs_outcome.opc_request_id,
            jobs_outcome.text,
            Some(now_ms + backoff_ms),
        ));
    }

    if !jobs_outcome.ok() {
        return Ok(RunResult::error(
            "list-jobs",
            jobs_outcome.status,
            jobs_outcome.opc_request_id,
            jobs_outcome.text,
        ));
    }

    state.rate_limit_strikes = 0;
    state.next_allowed_attempt_ms = None;

    let jobs_payload: JobsEnvelope = serde_json::from_str(&jobs_outcome.text).unwrap_or_default();
    let mut relevant_jobs: Vec<JobSummary> = jobs_payload
        .items
        .into_iter()
        .chain(jobs_payload.data.into_iter())
        .map(JobSummary::from)
        .filter(|job| job.operation == "APPLY")
        .collect();

    relevant_jobs.sort_by(|a, b| millis_from_iso(&b.time_created).partial_cmp(&millis_from_iso(&a.time_created)).unwrap_or(std::cmp::Ordering::Equal));

    if let Some(successful_job) = relevant_jobs
        .iter()
        .find(|job| job.lifecycle_state == "SUCCEEDED")
        .cloned()
    {
        let should_notify = minutes_since_opt(successful_job.time_created.as_deref())
            .map(|m| m <= config.success_notify_lookback_minutes as f64)
            .unwrap_or(false)
            && state.last_success_notified_job_id.as_deref() != successful_job.id.as_deref();

        if should_notify {
            notify_discord(
                env,
                &[
                    "🎉 **Oracle VM stack succeeded**".to_string(),
                    format!("Stack: `{}`", config.stack_id),
                    format!("Job: `{}`", successful_job.id.clone().unwrap_or_else(|| "unknown".to_string())),
                    format!("Created: {}", successful_job.time_created.clone().unwrap_or_else(|| "unknown".to_string())),
                ]
                .join("\n"),
            )
            .await;
            state.last_success_notified_job_id = successful_job.id.clone();
            save_state(env, &state).await;
        }

        return Ok(RunResult {
            ok: true,
            action: "stopped".to_string(),
            reason: Some("successful apply job already exists".to_string()),
            stage: None,
            status: None,
            retry_after: None,
            opc_request_id: jobs_outcome.opc_request_id,
            next_allowed_attempt_ms: None,
            capacity: None,
            job: Some(successful_job),
            active_jobs: vec![],
            cooldown_minutes: None,
            age_minutes: None,
            trigger: meta,
            body: None,
        });
    }

    let failure_window_start_ms = now_ms - (config.failure_alert_window_hours as f64 * 60.0 * 60.0 * 1000.0);
    let recent_window_jobs: Vec<JobSummary> = relevant_jobs
        .iter()
        .filter(|job| millis_from_iso(&job.time_created) >= failure_window_start_ms)
        .cloned()
        .collect();

    if !recent_window_jobs.is_empty() && recent_window_jobs.iter().all(|job| job.lifecycle_state == "FAILED") {
        let newest_failure = recent_window_jobs.first().cloned();
        if let Some(job) = newest_failure {
            let should_notify = minutes_since_opt(job.time_created.as_deref())
                .map(|m| m <= config.failure_notify_lookback_minutes as f64)
                .unwrap_or(false)
                && state.last_failure_notified_job_id.as_deref() != job.id.as_deref();

            if should_notify {
                notify_discord(
                    env,
                    &[
                        "⚠️ **Oracle stack has failed continuously for the configured failure window**".to_string(),
                        format!("Stack: `{}`", config.stack_id),
                        format!("Jobs in window: {}", recent_window_jobs.len()),
                        format!("Latest failed job: `{}`", job.id.clone().unwrap_or_else(|| "unknown".to_string())),
                        format!("Latest failure time: {}", job.time_created.clone().unwrap_or_else(|| "unknown".to_string())),
                    ]
                    .join("\n"),
                )
                .await;
                state.last_failure_notified_job_id = job.id.clone();
                save_state(env, &state).await;
            }
        }
    }

    let active_jobs: Vec<JobSummary> = relevant_jobs
        .iter()
        .filter(|job| matches!(job.lifecycle_state.as_str(), "ACCEPTED" | "IN_PROGRESS" | "CANCELING"))
        .cloned()
        .collect();

    if !active_jobs.is_empty() {
        return Ok(RunResult {
            ok: true,
            action: "skipped".to_string(),
            reason: Some("active apply job already exists".to_string()),
            stage: None,
            status: None,
            retry_after: None,
            opc_request_id: jobs_outcome.opc_request_id,
            next_allowed_attempt_ms: None,
            capacity: None,
            job: None,
            active_jobs,
            cooldown_minutes: None,
            age_minutes: None,
            trigger: meta,
            body: None,
        });
    }

    if let Some(newest_job) = relevant_jobs.first().cloned() {
        if let Some(age_minutes) = minutes_since_opt(newest_job.time_created.as_deref()) {
            if age_minutes < config.cooldown_minutes as f64 && !meta.forced {
                return Ok(RunResult {
                    ok: true,
                    action: "skipped".to_string(),
                    reason: Some("cooldown".to_string()),
                    stage: None,
                    status: None,
                    retry_after: None,
                    opc_request_id: jobs_outcome.opc_request_id,
                    next_allowed_attempt_ms: None,
                    capacity: None,
                    job: Some(newest_job),
                    active_jobs: vec![],
                    cooldown_minutes: Some(config.cooldown_minutes),
                    age_minutes: Some(age_minutes),
                    trigger: meta,
                    body: None,
                });
            }
        }
    }

    let mut capacity_result: Option<CapacityGateResult> = None;
    if let Some(capacity_config) = &config.capacity {
        let capacity_outcome = oracle.create_capacity_report(capacity_config).await?;

        if capacity_outcome.status == 429 {
            let backoff_ms = compute_backoff_ms(&capacity_outcome.retry_after, state.rate_limit_strikes);
            state.rate_limit_strikes += 1;
            state.next_allowed_attempt_ms = Some(now_ms + backoff_ms);
            save_state(env, &state).await;

            return Ok(RunResult::backoff(
                "capacity-report",
                capacity_outcome.status,
                capacity_outcome.retry_after,
                capacity_outcome.opc_request_id,
                capacity_outcome.text,
                Some(now_ms + backoff_ms),
            ));
        }

        if !capacity_outcome.ok() {
            return Ok(RunResult::error(
                "capacity-report",
                capacity_outcome.status,
                capacity_outcome.opc_request_id,
                capacity_outcome.text,
            ));
        }

        let capacity_json: ComputeCapacityReportResponse = serde_json::from_str(&capacity_outcome.text).unwrap_or_default();
        let availability = capacity_json.shape_availabilities.into_iter().next().unwrap_or_default();
        let gate = CapacityGateResult {
            enabled: true,
            checked_at: iso_now(),
            status: availability.availability_status.unwrap_or_else(|| "UNKNOWN".to_string()),
            available_count: availability.available_count,
            availability_domain: Some(capacity_config.availability_domain.clone()),
            shape: Some(capacity_config.instance_shape.clone()),
            fault_domain: capacity_config.fault_domain.clone(),
        };

        let passes = gate.status == "AVAILABLE" && gate.available_count.unwrap_or(0) > 0;
        capacity_result = Some(gate.clone());

        if !passes && !meta.forced {
            state.last_capacity_status = Some(gate.status.clone());
            state.last_capacity_checked_at = Some(gate.checked_at.clone());
            save_state(env, &state).await;

            return Ok(RunResult {
                ok: true,
                action: "skipped".to_string(),
                reason: Some("capacity gate blocked create".to_string()),
                stage: None,
                status: None,
                retry_after: None,
                opc_request_id: capacity_outcome.opc_request_id,
                next_allowed_attempt_ms: None,
                capacity: Some(gate),
                job: None,
                active_jobs: vec![],
                cooldown_minutes: None,
                age_minutes: None,
                trigger: meta,
                body: None,
            });
        }
    }

    let create_outcome = oracle.create_apply_job().await?;
    if create_outcome.status == 429 {
        let backoff_ms = compute_backoff_ms(&create_outcome.retry_after, state.rate_limit_strikes);
        state.rate_limit_strikes += 1;
        state.next_allowed_attempt_ms = Some(now_ms + backoff_ms);
        save_state(env, &state).await;

        return Ok(RunResult::backoff(
            "create-apply-job",
            create_outcome.status,
            create_outcome.retry_after,
            create_outcome.opc_request_id,
            create_outcome.text,
            Some(now_ms + backoff_ms),
        ));
    }

    if !create_outcome.ok() {
        return Ok(RunResult::error(
            "create-apply-job",
            create_outcome.status,
            create_outcome.opc_request_id,
            create_outcome.text,
        ));
    }

    state.rate_limit_strikes = 0;
    state.next_allowed_attempt_ms = None;
    if let Some(capacity) = &capacity_result {
        state.last_capacity_status = Some(capacity.status.clone());
        state.last_capacity_checked_at = Some(capacity.checked_at.clone());
    }
    save_state(env, &state).await;

    let created_job: JobSummary = serde_json::from_str::<JobSummaryRaw>(&create_outcome.text)
        .map(JobSummary::from)
        .unwrap_or_default();

    Ok(RunResult {
        ok: true,
        action: "created".to_string(),
        reason: None,
        stage: None,
        status: None,
        retry_after: None,
        opc_request_id: create_outcome.opc_request_id,
        next_allowed_attempt_ms: None,
        capacity: capacity_result,
        job: Some(created_job),
        active_jobs: vec![],
        cooldown_minutes: None,
        age_minutes: None,
        trigger: meta,
        body: None,
    })
}

#[derive(Debug, Clone)]
struct OracleClient {
    config: Config,
    imported_key: JsValue,
    rm_endpoint: String,
    compute_endpoint: String,
}

impl OracleClient {
    fn new(config: Config, imported_key: JsValue) -> Self {
        let rm_endpoint = format!(
            "https://resourcemanager.{}.oraclecloud.com",
            config.region
        );
        let compute_endpoint = format!("https://iaas.{}.oraclecloud.com", config.region);

        Self {
            config,
            imported_key,
            rm_endpoint,
            compute_endpoint,
        }
    }

    async fn list_jobs(&self) -> Result<HttpOutcome> {
        let path = format!(
            "/20180917/jobs?stackId={}&limit=100",
            urlencoding::encode(&self.config.stack_id)
        );

        self.oci_request(Method::Get, &self.rm_endpoint, &path, None, vec![])
            .await
    }

    async fn create_apply_job(&self) -> Result<HttpOutcome> {
        let payload = json!({
            "stackId": self.config.stack_id.clone(),
            "displayName": format!("cf-rust-auto-apply-{}", iso_now()),
            "jobOperationDetails": {
                "operation": "APPLY",
                "executionPlanStrategy": "AUTO_APPROVED"
            }
        });

        let retry_token = format!(
            "apply-{}-{}",
            short_stack_id(&self.config.stack_id),
            (now_ms() / 60000.0).floor() as i64
        );

        self.oci_request(
            Method::Post,
            &self.rm_endpoint,
            "/20180917/jobs",
            Some(payload),
            vec![("opc-retry-token".to_string(), retry_token)],
        )
        .await
    }

    async fn create_capacity_report(&self, capacity: &CapacityConfig) -> Result<HttpOutcome> {
        let mut shape_availability = serde_json::Map::new();
        shape_availability.insert("instanceShape".to_string(), json!(capacity.instance_shape.clone()));
        if let Some(fault_domain) = &capacity.fault_domain {
            shape_availability.insert("faultDomain".to_string(), json!(fault_domain));
        }

        let mut shape_config = serde_json::Map::new();
        if let Some(ocpus) = capacity.ocpus {
            shape_config.insert("ocpus".to_string(), json!(ocpus));
        }
        if let Some(memory_in_gbs) = capacity.memory_in_gbs {
            shape_config.insert("memoryInGBs".to_string(), json!(memory_in_gbs));
        }
        if let Some(baseline) = &capacity.baseline_ocpu_utilization {
            shape_config.insert("baselineOcpuUtilization".to_string(), json!(baseline));
        }
        if !shape_config.is_empty() {
            shape_availability.insert("instanceShapeConfig".to_string(), Value::Object(shape_config));
        }

        let payload = json!({
            "compartmentId": capacity.compartment_ocid.clone(),
            "availabilityDomain": capacity.availability_domain.clone(),
            "shapeAvailabilities": [Value::Object(shape_availability)]
        });

        self.oci_request(
            Method::Post,
            &self.compute_endpoint,
            "/20160918/computeCapacityReports",
            Some(payload),
            vec![("opc-retry-token".to_string(), format!("cap-{}-{}", short_stack_id(&self.config.stack_id), (now_ms() / 60000.0).floor() as i64))],
        )
        .await
    }

    async fn oci_request(
        &self,
        method: Method,
        endpoint: &str,
        path_and_query: &str,
        body: Option<Value>,
        extra_headers: Vec<(String, String)>,
    ) -> Result<HttpOutcome> {
        let upper_method = method.to_string().to_ascii_uppercase();
        let url = format!("{}{}", endpoint, path_and_query);
        let host = Url::parse(&url)
            .map_err(|e| Error::RustError(format!("invalid OCI url {url}: {e}")))?
            .host_str()
            .ok_or_else(|| Error::RustError(format!("missing host in OCI url: {url}")))?
            .to_string();

        let date = rfc7231_now();
        let headers = Headers::new();
        headers.set("date", &date)?;
        headers.set("host", &host)?;
        headers.set("accept", "application/json")?;
        headers.set("opc-request-id", &random_request_id())?;

        let mut body_text = String::new();
        let mut has_body = false;
        let mut headers_to_sign = vec!["date".to_string(), "(request-target)".to_string(), "host".to_string()];

        if let Some(body_value) = body {
            body_text = serde_json::to_string(&body_value)
                .map_err(|e| Error::RustError(format!("failed to serialize OCI request body: {e}")))?;
            let body_bytes = body_text.as_bytes().to_vec();
            let body_hash = sha256_base64(body_bytes.clone()).await?;

            headers.set("content-type", "application/json")?;
            headers.set("content-length", &body_bytes.len().to_string())?;
            headers.set("x-content-sha256", &body_hash)?;

            headers_to_sign.push("content-length".to_string());
            headers_to_sign.push("content-type".to_string());
            headers_to_sign.push("x-content-sha256".to_string());
            has_body = true;
        }

        for (name, value) in extra_headers {
            headers.set(&name, &value)?;
        }

        let signing_string = build_signing_string(
            &upper_method,
            path_and_query,
            &host,
            &date,
            &headers,
            &headers_to_sign,
        )?;
        let signature = sign_string(signing_string, self.imported_key.clone()).await?;

        let authorization = format!(
            "Signature version=\"1\",keyId=\"{}/{}/{}\",algorithm=\"rsa-sha256\",headers=\"{}\",signature=\"{}\"",
            self.config.tenancy_ocid,
            self.config.user_ocid,
            self.config.fingerprint,
            headers_to_sign.join(" "),
            signature
        );
        headers.set("authorization", &authorization)?;

        let mut init = RequestInit::new();
        init.with_method(method);
        init.with_headers(headers);
        if has_body {
            init.with_body(Some(JsValue::from_str(&body_text)));
        }

        let request = Request::new_with_init(&url, &init)?;
        let mut response = Fetch::Request(request).send().await?;
        let status = response.status_code();
        let retry_after = response.headers().get("retry-after")?;
        let opc_request_id = response.headers().get("opc-request-id")?;
        let text = response.text().await.unwrap_or_default();

        Ok(HttpOutcome {
            status,
            text,
            retry_after,
            opc_request_id,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    tenancy_ocid: String,
    user_ocid: String,
    fingerprint: String,
    region: String,
    stack_id: String,
    private_key_pem: String,
    cooldown_minutes: u32,
    failure_alert_window_hours: u32,
    success_notify_lookback_minutes: u32,
    failure_notify_lookback_minutes: u32,
    capacity: Option<CapacityConfig>,
}

impl Config {
    fn from_env(env: &Env) -> Result<Self> {
        let tenancy_ocid = required_var(env, "OCI_TENANCY_OCID")?;
        let user_ocid = required_var(env, "OCI_USER_OCID")?;
        let fingerprint = required_var(env, "OCI_FINGERPRINT")?;
        let region = required_var(env, "OCI_REGION")?;
        let stack_id = required_var(env, "OCI_STACK_OCID")?;
        let private_key_pem = required_var(env, "OCI_PRIVATE_KEY_PEM")?;

        let enable_capacity_gate = optional_var(env, "ENABLE_CAPACITY_GATE")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(true);

        let capacity = if enable_capacity_gate {
            let compartment_ocid = optional_var(env, "OCI_COMPARTMENT_OCID");
            let availability_domain = optional_var(env, "OCI_AVAILABILITY_DOMAIN");
            let instance_shape = optional_var(env, "OCI_INSTANCE_SHAPE");

            match (compartment_ocid, availability_domain, instance_shape) {
                (Some(compartment_ocid), Some(availability_domain), Some(instance_shape)) => Some(CapacityConfig {
                    compartment_ocid,
                    availability_domain,
                    instance_shape,
                    fault_domain: optional_var(env, "OCI_FAULT_DOMAIN"),
                    ocpus: optional_f64(env, "OCI_SHAPE_OCPUS"),
                    memory_in_gbs: optional_f64(env, "OCI_SHAPE_MEMORY_GBS"),
                    baseline_ocpu_utilization: optional_var(env, "OCI_SHAPE_BASELINE_OCPU_UTILIZATION"),
                }),
                _ => None,
            }
        } else {
            None
        };

        Ok(Self {
            tenancy_ocid,
            user_ocid,
            fingerprint,
            region,
            stack_id,
            private_key_pem,
            cooldown_minutes: positive_u32(optional_var(env, "COOLDOWN_MINUTES"), 5),
            failure_alert_window_hours: positive_u32(optional_var(env, "FAILURE_ALERT_WINDOW_HOURS"), 3),
            success_notify_lookback_minutes: positive_u32(optional_var(env, "SUCCESS_NOTIFY_LOOKBACK_MINUTES"), 999),
            failure_notify_lookback_minutes: positive_u32(optional_var(env, "FAILURE_NOTIFY_LOOKBACK_MINUTES"), 15),
            capacity,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CapacityConfig {
    compartment_ocid: String,
    availability_domain: String,
    instance_shape: String,
    fault_domain: Option<String>,
    ocpus: Option<f64>,
    memory_in_gbs: Option<f64>,
    baseline_ocpu_utilization: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedState {
    next_allowed_attempt_ms: Option<f64>,
    rate_limit_strikes: u32,
    last_success_notified_job_id: Option<String>,
    last_failure_notified_job_id: Option<String>,
    last_capacity_status: Option<String>,
    last_capacity_checked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TriggerMeta {
    trigger: String,
    cron: Option<String>,
    forced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunResult {
    ok: bool,
    action: String,
    reason: Option<String>,
    stage: Option<String>,
    status: Option<u16>,
    retry_after: Option<String>,
    opc_request_id: Option<String>,
    next_allowed_attempt_ms: Option<f64>,
    capacity: Option<CapacityGateResult>,
    job: Option<JobSummary>,
    active_jobs: Vec<JobSummary>,
    cooldown_minutes: Option<u32>,
    age_minutes: Option<f64>,
    trigger: TriggerMeta,
    body: Option<String>,
}

impl RunResult {
    fn skipped(reason: &str, body: Value) -> Self {
        Self {
            ok: true,
            action: "skipped".to_string(),
            reason: Some(reason.to_string()),
            stage: None,
            status: None,
            retry_after: None,
            opc_request_id: None,
            next_allowed_attempt_ms: None,
            capacity: None,
            job: None,
            active_jobs: vec![],
            cooldown_minutes: None,
            age_minutes: None,
            trigger: TriggerMeta {
                trigger: "system".to_string(),
                cron: None,
                forced: false,
            },
            body: Some(body.to_string()),
        }
    }

    fn error(stage: &str, status: u16, opc_request_id: Option<String>, body: String) -> Self {
        Self {
            ok: false,
            action: "error".to_string(),
            reason: None,
            stage: Some(stage.to_string()),
            status: Some(status),
            retry_after: None,
            opc_request_id,
            next_allowed_attempt_ms: None,
            capacity: None,
            job: None,
            active_jobs: vec![],
            cooldown_minutes: None,
            age_minutes: None,
            trigger: TriggerMeta {
                trigger: "system".to_string(),
                cron: None,
                forced: false,
            },
            body: Some(safe_truncate(&body, 2500)),
        }
    }

    fn backoff(
        stage: &str,
        status: u16,
        retry_after: Option<String>,
        opc_request_id: Option<String>,
        body: String,
        next_allowed_attempt_ms: Option<f64>,
    ) -> Self {
        Self {
            ok: false,
            action: "backoff".to_string(),
            reason: None,
            stage: Some(stage.to_string()),
            status: Some(status),
            retry_after,
            opc_request_id,
            next_allowed_attempt_ms,
            capacity: None,
            job: None,
            active_jobs: vec![],
            cooldown_minutes: None,
            age_minutes: None,
            trigger: TriggerMeta {
                trigger: "system".to_string(),
                cron: None,
                forced: false,
            },
            body: Some(safe_truncate(&body, 2500)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct JobsEnvelope {
    #[serde(default)]
    items: Vec<JobSummaryRaw>,
    #[serde(default)]
    data: Vec<JobSummaryRaw>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct JobSummaryRaw {
    id: Option<String>,
    display_name: Option<String>,
    #[serde(alias = "display-name")]
    legacy_display_name: Option<String>,
    lifecycle_state: Option<String>,
    #[serde(alias = "lifecycle-state")]
    legacy_lifecycle_state: Option<String>,
    operation: Option<String>,
    job_operation_details: Option<JobOperationDetails>,
    #[serde(alias = "job-operation-details")]
    legacy_job_operation_details: Option<JobOperationDetails>,
    time_created: Option<String>,
    #[serde(alias = "time-created")]
    legacy_time_created: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct JobOperationDetails {
    operation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct JobSummary {
    id: Option<String>,
    display_name: Option<String>,
    lifecycle_state: String,
    operation: String,
    time_created: Option<String>,
}

impl From<JobSummaryRaw> for JobSummary {
    fn from(raw: JobSummaryRaw) -> Self {
        let lifecycle_state = raw
            .lifecycle_state
            .or(raw.legacy_lifecycle_state)
            .unwrap_or_default()
            .to_ascii_uppercase();
        let operation = raw
            .operation
            .or_else(|| raw.job_operation_details.and_then(|d| d.operation))
            .or_else(|| raw.legacy_job_operation_details.and_then(|d| d.operation))
            .unwrap_or_default()
            .to_ascii_uppercase();

        Self {
            id: raw.id,
            display_name: raw.display_name.or(raw.legacy_display_name),
            lifecycle_state,
            operation,
            time_created: raw.time_created.or(raw.legacy_time_created),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ComputeCapacityReportResponse {
    #[serde(default)]
    shape_availabilities: Vec<CapacityAvailability>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CapacityAvailability {
    availability_status: Option<String>,
    available_count: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CapacityGateResult {
    enabled: bool,
    checked_at: String,
    status: String,
    available_count: Option<i64>,
    availability_domain: Option<String>,
    shape: Option<String>,
    fault_domain: Option<String>,
}

#[derive(Debug, Clone)]
struct HttpOutcome {
    status: u16,
    text: String,
    retry_after: Option<String>,
    opc_request_id: Option<String>,
}

impl HttpOutcome {
    fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

fn required_var(env: &Env, key: &str) -> Result<String> {
    let value = env.var(key)?.to_string();
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Err(Error::RustError(format!("Missing required binding: {key}")));
    }
    Ok(trimmed)
}

fn optional_var(env: &Env, key: &str) -> Option<String> {
    env.var(key)
        .ok()
        .map(|v| v.to_string())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn optional_f64(env: &Env, key: &str) -> Option<f64> {
    optional_var(env, key).and_then(|v| v.parse::<f64>().ok())
}

fn positive_u32(value: Option<String>, fallback: u32) -> u32 {
    value
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(fallback)
}

async fn import_signing_key(pem: &str) -> Result<JsValue> {
    let bytes = pem_to_pkcs8_bytes(pem)?;
    let key = import_pkcs8_private_key(bytes)
        .await
        .map_err(js_error_to_worker)?;
    Ok(key)
}

fn pem_to_pkcs8_bytes(pem: &str) -> Result<Vec<u8>> {
    let normalized = pem.trim().trim_matches('"').replace("\\n", "\n");
    let cleaned = normalized
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
        .replace("-----END RSA PRIVATE KEY-----", "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();

    if cleaned.is_empty() {
        return Err(Error::RustError(
            "Private key is empty after PEM cleanup".to_string(),
        ));
    }

    BASE64_STANDARD
        .decode(cleaned)
        .map_err(|e| Error::RustError(format!("Failed to decode OCI private key PEM: {e}")))
}

async fn sha256_base64(bytes: Vec<u8>) -> Result<String> {
    let value = sha256_base64_from_bytes(bytes)
        .await
        .map_err(js_error_to_worker)?;
    Ok(js_value_to_string(value))
}

async fn sign_string(input: String, key: JsValue) -> Result<String> {
    let value = sign_string_base64(input, key)
        .await
        .map_err(js_error_to_worker)?;
    Ok(js_value_to_string(value))
}

fn build_signing_string(
    method: &str,
    path_and_query: &str,
    host: &str,
    date: &str,
    headers: &Headers,
    headers_to_sign: &[String],
) -> Result<String> {
    let mut parts = Vec::with_capacity(headers_to_sign.len());

    for name in headers_to_sign {
        match name.as_str() {
            "(request-target)" => {
                parts.push(format!("(request-target): {} {}", method.to_ascii_lowercase(), path_and_query));
            }
            "date" => parts.push(format!("date: {date}")),
            "host" => parts.push(format!("host: {host}")),
            other => {
                let value = headers
                    .get(other)?
                    .ok_or_else(|| Error::RustError(format!("Missing signed header value for {other}")))?;
                parts.push(format!("{}: {}", other, value));
            }
        }
    }

    Ok(parts.join("\n"))
}

async fn load_state(env: &Env) -> Result<PersistedState> {
    let kv = match env.kv("STATE_KV") {
        Ok(kv) => kv,
        Err(_) => return Ok(PersistedState::default()),
    };

    match kv.get(STATE_KEY).text().await {
        Ok(Some(text)) => serde_json::from_str(&text)
            .map_err(|e| Error::RustError(format!("Failed to parse STATE_KV payload: {e}"))),
        Ok(None) => Ok(PersistedState::default()),
        Err(err) => Err(err.into()),
    }
}

async fn save_state(env: &Env, state: &PersistedState) {
    let Ok(kv) = env.kv("STATE_KV") else {
        return;
    };

    let Ok(serialized) = serde_json::to_string(state) else {
        return;
    };

    if let Ok(builder) = kv.put(STATE_KEY, serialized) {
        let _ = builder.execute().await;
    }
}

async fn notify_discord(env: &Env, message: &str) {
    let Some(url) = optional_var(env, "DISCORD_WEBHOOK_URL") else {
        return;
    };

    let headers = Headers::new();
    let _ = headers.set("content-type", "application/json");

    let payload = json!({ "content": message }).to_string();
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_headers(headers);
    init.with_body(Some(JsValue::from_str(&payload)));

    match Request::new_with_init(&url, &init) {
        Ok(request) => match Fetch::Request(request).send().await {
            Ok(mut response) => {
                if !(200..300).contains(&response.status_code()) {
                    let text = response.text().await.unwrap_or_default();
                    console_warn!(
                        "Discord webhook failed status={} body={}",
                        response.status_code(),
                        safe_truncate(&text, 500)
                    );
                }
            }
            Err(err) => console_warn!("Discord webhook exception: {}", err),
        },
        Err(err) => console_warn!("Discord request build exception: {}", err),
    }
}

fn compute_backoff_ms(retry_after: &Option<String>, strikes: u32) -> f64 {
    if let Some(value) = retry_after {
        if let Ok(seconds) = value.parse::<f64>() {
            return seconds * 1000.0 + random_jitter_ms(15_000.0);
        }
    }

    let multiplier = 2_f64.powi((strikes.min(4)) as i32);
    (60_000.0 * multiplier).min(15.0 * 60_000.0) + random_jitter_ms(20_000.0)
}

fn safe_truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        format!("{}...[truncated]", &value[..max])
    }
}

fn iso_now() -> String {
    Date::new_0().to_iso_string().into()
}

fn rfc7231_now() -> String {
    let value: JsString = Date::new_0().to_utc_string();
    value.into()
}

fn now_ms() -> f64 {
    Date::now()
}

fn millis_from_iso(value: &Option<String>) -> f64 {
    value
        .as_ref()
        .map(|v| Date::parse(v))
        .filter(|v| v.is_finite())
        .unwrap_or(f64::NEG_INFINITY)
}

fn minutes_since_opt(value: Option<&str>) -> Option<f64> {
    let value = value?;
    let ms = Date::parse(value);
    if ms.is_finite() {
        Some((Date::now() - ms) / 60_000.0)
    } else {
        None
    }
}

fn random_jitter_ms(max: f64) -> f64 {
    Math::random() * max
}

fn random_request_id() -> String {
    format!(
        "cf-rust-{}-{:08x}",
        (Date::now() / 1000.0).floor() as i64,
        (Math::random() * 4_294_967_295.0) as u32
    )
}

fn short_stack_id(value: &str) -> String {
    value.chars().rev().take(12).collect::<String>().chars().rev().collect()
}

fn js_error_to_worker(err: JsValue) -> Error {
    Error::RustError(format!("JS bridge error: {}", js_value_to_string(err)))
}

fn js_value_to_string(value: JsValue) -> String {
    if let Some(text) = value.as_string() {
        return text;
    }
    if let Ok(js_string) = value.clone().dyn_into::<JsString>() {
        return js_string.into();
    }
    format!("{:?}", value)
}

fn json_response(value: Value, status: u16) -> Result<Response> {
    Ok(Response::from_json(&value)?.with_status(status))
}
