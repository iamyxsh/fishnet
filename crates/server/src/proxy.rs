use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::alert::{AlertSeverity, AlertType};
use crate::llm_guard::{
    check_prompt_drift, check_prompt_size, count_prompt_chars, extract_system_prompt, GuardDecision,
};
use crate::constants;
use crate::state::AppState;

pub async fn handler(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    uri: axum::http::Uri,
    body: axum::body::Bytes,
) -> Response {
    let path = uri.path();
    let path = path.strip_prefix(constants::PROXY_PATH_PREFIX).unwrap_or(path);
    let (provider, rest) = match path.split_once('/') {
        Some((p, r)) => (p.to_string(), format!("/{r}")),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid proxy path" })),
            )
                .into_response();
        }
    };

    let upstream_base = match provider.as_str() {
        "openai" => constants::OPENAI_API_BASE,
        "anthropic" => constants::ANTHROPIC_API_BASE,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("unknown provider: {provider}")
                })),
            )
                .into_response();
        }
    };

    let config = state.config();

    if config.llm.rate_limit_per_minute > 0 {
        if let Err(retry_after) = state
            .proxy_rate_limiter
            .check_and_record(&provider, config.llm.rate_limit_per_minute)
            .await
        {
            if config.alerts.rate_limit_hit {
                state
                    .alert_store
                    .create(
                        AlertType::RateLimitHit,
                        AlertSeverity::Warning,
                        &provider,
                        format!(
                            "Rate limit exceeded for {provider}. Retry after {retry_after}s."
                        ),
                    )
                    .await;
            }
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": format!("rate limit exceeded, retry after {retry_after}s"),
                    "retry_after_seconds": retry_after
                })),
            )
                .into_response();
        }
    }

    let needs_guards =
        config.llm.prompt_drift.enabled || config.llm.prompt_size_guard.enabled;

    let is_json_body = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map_or(false, |ct| ct.contains("application/json"));

    let body_json: Option<serde_json::Value> =
        if needs_guards && !body.is_empty() && is_json_body {
            match serde_json::from_slice(&body) {
                Ok(val) => Some(val),
                Err(e) => {
                    eprintln!("[fishnet] invalid JSON body: {e}");
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "request body is not valid JSON"
                        })),
                    )
                        .into_response();
                }
            }
        } else {
            None
        };

    if let Some(ref body_val) = body_json {
        let system_prompt = extract_system_prompt(&provider, body_val);
        let drift_result = check_prompt_drift(
            &state.baseline_store,
            &state.alert_store,
            &provider,
            system_prompt.as_deref(),
            &config.llm.prompt_drift,
            config.alerts.prompt_drift,
        )
        .await;

        if let GuardDecision::Deny(msg) = drift_result {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": msg })),
            )
                .into_response();
        }

        let total_chars = count_prompt_chars(&provider, body_val);
        let size_result = check_prompt_size(
            &state.alert_store,
            &provider,
            total_chars,
            &config.llm.prompt_size_guard,
            config.alerts.prompt_size,
        )
        .await;

        if let GuardDecision::Deny(msg) = size_result {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": msg })),
            )
                .into_response();
        }
    }

    let target_url = if let Some(query) = uri.query() {
        format!("{upstream_base}{rest}?{query}")
    } else {
        format!("{upstream_base}{rest}")
    };

    let mut upstream_req = state.http_client.request(method, &target_url);

    for (name, value) in &headers {
        let name_str = name.as_str();
        if matches!(
            name_str,
            "host" | "transfer-encoding" | "connection" | "keep-alive"
        ) {
            continue;
        }
        upstream_req = upstream_req.header(name.clone(), value.clone());
    }

    if !body.is_empty() {
        upstream_req = upstream_req.body(body.clone());
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("[fishnet] upstream request failed: {e}");
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "error": "upstream provider is unavailable"
                })),
            )
                .into_response();
        }
    };

    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response_builder = Response::builder().status(status);

    for (name, value) in upstream_resp.headers() {
        let name_str = name.as_str();
        if matches!(name_str, "transfer-encoding" | "connection" | "keep-alive") {
            continue;
        }
        if let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) {
            response_builder = response_builder.header(name.clone(), header_value);
        }
    }

    let body_stream = upstream_resp.bytes_stream();
    let body = Body::from_stream(body_stream);

    match response_builder.body(body) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("[fishnet] failed to build response: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "internal proxy error" })),
            )
                .into_response()
        }
    }
}
