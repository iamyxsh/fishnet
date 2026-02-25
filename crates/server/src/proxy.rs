use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, Mac};
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::{Decimal, RoundingStrategy};
use sha2::Sha256;
use std::str::FromStr;
use url::form_urlencoded;

use crate::alert::{AlertSeverity, AlertType};
use crate::constants;
use crate::llm_guard::{
    GuardDecision, check_prompt_drift, check_prompt_size, count_prompt_chars, extract_system_prompt,
};
use crate::state::AppState;
use crate::vault::DecryptedCredential;

type HmacSha256 = Hmac<Sha256>;
const USD_MICROS_SCALE: i64 = 1_000_000;

pub async fn handler(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: axum::body::Bytes,
) -> Response {
    let path = uri.path();
    let path = path
        .strip_prefix(constants::PROXY_PATH_PREFIX)
        .unwrap_or(path);
    let (provider, rest) = match path.split_once('/') {
        Some((p, r)) => (p.to_string(), format!("/{r}")),
        None => {
            return json_error(StatusCode::BAD_REQUEST, "invalid proxy path");
        }
    };

    let upstream_base = match provider.as_str() {
        "openai" => constants::OPENAI_API_BASE,
        "anthropic" => constants::ANTHROPIC_API_BASE,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                &format!("unknown provider: {provider}"),
            );
        }
    };

    let config = state.config();
    if config.llm.rate_limit_per_minute > 0
        && let Err(retry_after) = state
            .proxy_rate_limiter
            .check_and_record(&provider, config.llm.rate_limit_per_minute)
            .await
    {
        if config.alerts.rate_limit_hit {
            if let Err(e) = state
                .alert_store
                .create(
                    AlertType::RateLimitHit,
                    AlertSeverity::Warning,
                    &provider,
                    format!("Rate limit exceeded for {provider}. Retry after {retry_after}s."),
                )
                .await
            {
                eprintln!("[fishnet] failed to create rate limit alert: {e}");
            }
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

    if let Err(resp) = enforce_llm_guards(&state, &provider, &headers, &body).await {
        return resp;
    }

    let target_url = with_query(upstream_base, &rest, uri.query());
    let (extra_headers, credential_id) = {
        let credential = match state.credential_store.decrypt_for_service(&provider).await {
            Ok(Some(cred)) => cred,
            Ok(None) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    &format!("credential not found for service: {provider}"),
                );
            }
            Err(e) => {
                eprintln!("[fishnet] failed to decrypt credential for {provider}: {e}");
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to access credential vault",
                );
            }
        };

        let mut extra_headers: Vec<(String, HeaderValue)> = Vec::new();
        match provider.as_str() {
            "openai" => {
                let auth_header = format!("Bearer {}", credential.key.as_str());
                let auth_value = match HeaderValue::from_str(&auth_header) {
                    Ok(v) => v,
                    Err(_) => {
                        return json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "invalid credential format for openai",
                        );
                    }
                };
                extra_headers.push(("authorization".to_string(), auth_value));
            }
            "anthropic" => {
                let api_key_value = match HeaderValue::from_str(credential.key.as_str()) {
                    Ok(v) => v,
                    Err(_) => {
                        return json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "invalid credential format for anthropic",
                        );
                    }
                };
                extra_headers.push(("x-api-key".to_string(), api_key_value));
            }
            _ => {}
        }

        (extra_headers, credential.id)
    };

    if let Err(e) = state.credential_store.touch_last_used(&credential_id).await {
        eprintln!("[fishnet] failed to update credential last_used_at: {e}");
    }

    let skip_headers = vec!["authorization".to_string(), "x-api-key".to_string()];
    let upstream_resp = match send_upstream(
        &state,
        method,
        &headers,
        &target_url,
        Some(body),
        &skip_headers,
        &extra_headers,
    )
    .await
    {
        Ok(resp) => resp,
        Err(resp) => return resp,
    };

    build_proxy_response(upstream_resp)
}

pub async fn binance_handler(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: axum::body::Bytes,
) -> Response {
    let config = state.config();
    if !config.binance.enabled {
        return json_error(StatusCode::FORBIDDEN, "binance proxy is disabled");
    }

    let Some(rest) = uri.path().strip_prefix("/binance") else {
        return json_error(StatusCode::BAD_REQUEST, "invalid binance proxy path");
    };
    if rest.is_empty() || !rest.starts_with('/') {
        return json_error(StatusCode::BAD_REQUEST, "invalid binance proxy path");
    }

    let route_path = rest.to_string();
    if !(route_path.starts_with("/api/") || route_path.starts_with("/sapi/")) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "binance path must start with /api or /sapi",
        );
    }

    if method == Method::POST && route_path.starts_with("/sapi/v1/capital/withdraw/") {
        return json_error(
            StatusCode::FORBIDDEN,
            "endpoint is hard-blocked by fishnet policy: withdrawals are disabled",
        );
    }

    let is_read_only = method == Method::GET
        && (route_path.starts_with("/api/v3/ticker/") || route_path == "/api/v3/klines");
    let is_order = method == Method::POST && route_path == "/api/v3/order";
    let is_delete_open_orders = method == Method::DELETE && route_path == "/api/v3/openOrders";

    if is_delete_open_orders && !config.binance.allow_delete_open_orders {
        return json_error(
            StatusCode::FORBIDDEN,
            "endpoint blocked by default policy: DELETE /api/v3/openOrders",
        );
    }

    if !is_read_only && !is_order && !is_delete_open_orders {
        return json_error(
            StatusCode::FORBIDDEN,
            "binance endpoint is not allowed by policy",
        );
    }

    let mut parsed_params: Vec<(String, String)> = Vec::new();
    if let Some(query) = uri.query() {
        parsed_params.extend(parse_form_pairs(query));
    }

    if !body.is_empty() {
        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s,
            Err(_) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "binance request body must be UTF-8 form data",
                );
            }
        };
        parsed_params.extend(parse_form_pairs(body_str));
    }

    let _order_guard = if is_order {
        // Serialize order cap checks + spend recording to prevent concurrent overspend.
        Some(state.binance_order_lock.lock().await)
    } else {
        None
    };

    let mut order_value_micros = None;
    if is_order {
        let value_micros = match parse_binance_order_value_usd(&parsed_params) {
            Ok(v) => v,
            Err(msg) => return json_error(StatusCode::BAD_REQUEST, &msg),
        };

        let max_order_micros = config_usd_to_micros(config.binance.max_order_value_usd);
        if max_order_micros > 0 && value_micros > max_order_micros {
            return json_error(
                StatusCode::FORBIDDEN,
                &format!(
                    "order value ${} exceeds max_order_value_usd ${}",
                    format_usd_micros(value_micros),
                    format_usd_micros(max_order_micros),
                ),
            );
        }

        let daily_cap_micros = config_usd_to_micros(config.binance.daily_volume_cap_usd);
        if daily_cap_micros > 0 {
            let spent_today_micros = state
                .spend_store
                .get_spent_today_micros("binance")
                .await
                .unwrap_or(0);
            let projected_micros = match spent_today_micros.checked_add(value_micros) {
                Some(total) => total,
                None => {
                    return json_error(
                        StatusCode::FORBIDDEN,
                        "daily binance volume cap exceeded: projected volume overflowed supported range",
                    );
                }
            };
            if projected_micros > daily_cap_micros {
                return json_error(
                    StatusCode::FORBIDDEN,
                    &format!(
                        "daily binance volume cap exceeded: ${} + ${} > ${}",
                        format_usd_micros(spent_today_micros),
                        format_usd_micros(value_micros),
                        format_usd_micros(daily_cap_micros),
                    ),
                );
            }
        }

        order_value_micros = Some(value_micros);
    }

    let mut extra_headers: Vec<(String, HeaderValue)> = Vec::new();
    let skip_headers = vec![
        "authorization".to_string(),
        "x-api-key".to_string(),
        "x-mbx-apikey".to_string(),
    ];
    let binance_base_url = if config.binance.base_url.trim().is_empty() {
        constants::BINANCE_API_BASE.to_string()
    } else {
        config.binance.base_url.trim_end_matches('/').to_string()
    };

    let mut target_url = with_query(&binance_base_url, &route_path, uri.query());
    let mut outbound_body = if is_read_only {
        Some(body.clone())
    } else {
        None
    };

    if !is_read_only {
        let (api_key, api_secret) = match load_binance_credentials(&state).await {
            Ok(creds) => creds,
            Err(resp) => return resp,
        };

        if !parsed_params.iter().any(|(k, _)| k == "timestamp") {
            parsed_params.push((
                "timestamp".to_string(),
                chrono::Utc::now().timestamp_millis().to_string(),
            ));
        }
        if config.binance.recv_window_ms > 0
            && !parsed_params.iter().any(|(k, _)| k == "recvWindow")
        {
            parsed_params.push((
                "recvWindow".to_string(),
                config.binance.recv_window_ms.to_string(),
            ));
        }

        let unsigned_query = serialize_form_pairs(&parsed_params);
        let signature = match hmac_sha256_hex(api_secret.key.as_bytes(), unsigned_query.as_bytes())
        {
            Ok(sig) => sig,
            Err(msg) => {
                return json_error(StatusCode::INTERNAL_SERVER_ERROR, &msg);
            }
        };
        parsed_params.push(("signature".to_string(), signature));
        let signed_query = serialize_form_pairs(&parsed_params);
        target_url = format!("{binance_base_url}{route_path}?{signed_query}");

        let api_key_value = match HeaderValue::from_str(api_key.key.as_str()) {
            Ok(v) => v,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "invalid credential format for binance api key",
                );
            }
        };
        extra_headers.push(("x-mbx-apikey".to_string(), api_key_value));

        if let Err(e) = state.credential_store.touch_last_used(&api_key.id).await {
            eprintln!("[fishnet] failed to update binance api key last_used_at: {e}");
        }
        if let Err(e) = state.credential_store.touch_last_used(&api_secret.id).await {
            eprintln!("[fishnet] failed to update binance api secret last_used_at: {e}");
        }
        // Explicitly drop zeroizing key wrappers before sending the upstream request.
        drop(api_secret);
        drop(api_key);
    } else if !body.is_empty() {
        outbound_body = Some(body.clone());
    }

    let upstream_resp = match send_upstream(
        &state,
        method,
        &headers,
        &target_url,
        outbound_body,
        &skip_headers,
        &extra_headers,
    )
    .await
    {
        Ok(resp) => resp,
        Err(resp) => return resp,
    };

    if is_order
        && upstream_resp.status().is_success()
        && let Some(cost_micros) = order_value_micros
    {
        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        if let Err(e) = state
            .spend_store
            .record_spend_micros("binance", &today, cost_micros)
            .await
        {
            eprintln!("[fishnet] failed to record binance spend: {e}");
        }
    }

    build_proxy_response(upstream_resp)
}

pub async fn custom_handler(
    State(state): State<AppState>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: axum::body::Bytes,
) -> Response {
    let path = uri.path();
    let path = path.strip_prefix("/custom/").unwrap_or(path);
    let (name, rest) = match path.split_once('/') {
        Some((name, rest)) if !name.is_empty() => (name.to_string(), format!("/{rest}")),
        _ => {
            return json_error(StatusCode::BAD_REQUEST, "invalid custom proxy path");
        }
    };

    let config = state.config();
    let Some(service_cfg) = config.custom.get(&name).cloned() else {
        return json_error(
            StatusCode::BAD_REQUEST,
            &format!("unknown custom service: {name}"),
        );
    };

    if service_cfg.base_url.trim().is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            &format!("custom service {name} has empty base_url"),
        );
    }

    if let Err(retry_after) = state
        .proxy_rate_limiter
        .check_and_record_with_window(
            &format!("custom:{name}"),
            service_cfg.rate_limit,
            service_cfg.rate_limit_window_seconds,
        )
        .await
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": format!("rate limit exceeded, retry after {retry_after}s"),
                "retry_after_seconds": retry_after
            })),
        )
            .into_response();
    }

    if service_cfg
        .blocked_endpoints
        .iter()
        .any(|pattern| endpoint_pattern_matches(pattern, &method, &rest))
    {
        return json_error(StatusCode::FORBIDDEN, "endpoint blocked by custom policy");
    }

    let mut extra_headers: Vec<(String, HeaderValue)> = Vec::new();
    let mut skip_headers = vec!["authorization".to_string(), "x-api-key".to_string()];

    let auth_header_name = service_cfg.auth_header.trim().to_string();
    if !auth_header_name.is_empty() {
        let credential = match load_custom_credential(&state, &name).await {
            Ok(Some(cred)) => cred,
            Ok(None) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    &format!("credential not found for custom service: {name}"),
                );
            }
            Err(resp) => return resp,
        };

        let header_name = match HeaderName::from_bytes(auth_header_name.as_bytes()) {
            Ok(v) => v,
            Err(_) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    &format!("invalid auth_header for custom service: {name}"),
                );
            }
        };
        let header_name_str = header_name.as_str().to_string();
        skip_headers.push(header_name_str.to_ascii_lowercase());

        let header_value = format!(
            "{}{}",
            service_cfg.auth_value_prefix,
            credential.key.as_str()
        );
        let header_value = match HeaderValue::from_str(&header_value) {
            Ok(v) => v,
            Err(_) => {
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("invalid credential value for custom service: {name}"),
                );
            }
        };
        extra_headers.push((header_name_str, header_value));

        if let Err(e) = state.credential_store.touch_last_used(&credential.id).await {
            eprintln!("[fishnet] failed to update custom credential last_used_at: {e}");
        }
    }

    let base_url = service_cfg.base_url.trim_end_matches('/');
    let target_url = with_query(base_url, &rest, uri.query());
    let upstream_resp = match send_upstream(
        &state,
        method,
        &headers,
        &target_url,
        Some(body),
        &skip_headers,
        &extra_headers,
    )
    .await
    {
        Ok(resp) => resp,
        Err(resp) => return resp,
    };

    build_proxy_response(upstream_resp)
}

async fn enforce_llm_guards(
    state: &AppState,
    provider: &str,
    headers: &HeaderMap,
    body: &axum::body::Bytes,
) -> Result<(), Response> {
    let config = state.config();
    let needs_guards = config.llm.prompt_drift.enabled || config.llm.prompt_size_guard.enabled;

    let is_json_body = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("application/json"));

    let body_json: Option<serde_json::Value> = if needs_guards && !body.is_empty() && is_json_body {
        match serde_json::from_slice(body) {
            Ok(val) => Some(val),
            Err(e) => {
                eprintln!("[fishnet] invalid JSON body: {e}");
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    "request body is not valid JSON",
                ));
            }
        }
    } else {
        None
    };

    if let Some(ref body_val) = body_json {
        let system_prompt = extract_system_prompt(provider, body_val);
        let drift_result = check_prompt_drift(
            &state.baseline_store,
            &state.alert_store,
            provider,
            system_prompt.as_deref(),
            &config.llm.prompt_drift,
            config.alerts.prompt_drift,
        )
        .await;

        if let GuardDecision::Deny(msg) = drift_result {
            return Err(json_error(StatusCode::FORBIDDEN, &msg));
        }

        let total_chars = count_prompt_chars(provider, body_val);
        let size_result = check_prompt_size(
            &state.alert_store,
            provider,
            total_chars,
            &config.llm.prompt_size_guard,
            config.alerts.prompt_size,
        )
        .await;

        if let GuardDecision::Deny(msg) = size_result {
            return Err(json_error(StatusCode::FORBIDDEN, &msg));
        }
    }

    Ok(())
}

fn parse_form_pairs(input: &str) -> Vec<(String, String)> {
    form_urlencoded::parse(input.as_bytes())
        .into_owned()
        .collect()
}

fn serialize_form_pairs(params: &[(String, String)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (k, v) in params {
        serializer.append_pair(k, v);
    }
    serializer.finish()
}

fn parse_binance_order_value_usd(params: &[(String, String)]) -> Result<i64, String> {
    let symbol = lookup_param(params, "symbol")
        .ok_or_else(|| "missing symbol in binance order request".to_string())?;

    if !is_usd_quoted_symbol(symbol) {
        return Err(format!(
            "unsupported symbol for USD valuation: {symbol}. use a USD-quoted pair (USDT/USDC/BUSD/FDUSD)"
        ));
    }

    if let Some(quote_qty) = lookup_param(params, "quoteOrderQty") {
        let value = parse_positive_decimal(quote_qty)
            .ok_or_else(|| "quoteOrderQty must be a positive number".to_string())?;
        return decimal_to_micros(value, RoundingStrategy::ToPositiveInfinity);
    }

    let price = lookup_param(params, "price")
        .and_then(parse_positive_decimal)
        .ok_or_else(|| "missing or invalid price in binance order request".to_string())?;
    let quantity = lookup_param(params, "quantity")
        .and_then(parse_positive_decimal)
        .ok_or_else(|| "missing or invalid quantity in binance order request".to_string())?;

    decimal_to_micros(price * quantity, RoundingStrategy::ToPositiveInfinity)
}

fn parse_positive_decimal(raw: &str) -> Option<Decimal> {
    let value = Decimal::from_str(raw).ok()?;
    if value.is_sign_positive() && !value.is_zero() {
        Some(value)
    } else {
        None
    }
}

fn config_usd_to_micros(raw: f64) -> i64 {
    if !raw.is_finite() || raw <= 0.0 {
        return 0;
    }
    let as_decimal = Decimal::from_str(&raw.to_string()).unwrap_or(Decimal::ZERO);
    decimal_to_micros(as_decimal, RoundingStrategy::ToZero).unwrap_or(0)
}

fn decimal_to_micros(value: Decimal, rounding: RoundingStrategy) -> Result<i64, String> {
    if value.is_sign_negative() {
        return Err("value cannot be negative".to_string());
    }
    let scaled = value * Decimal::from(USD_MICROS_SCALE);
    let rounded = scaled.round_dp_with_strategy(0, rounding);
    rounded
        .to_i64()
        .ok_or_else(|| "value is outside supported range".to_string())
}

fn format_usd_micros(micros: i64) -> String {
    format!("{:.2}", micros as f64 / USD_MICROS_SCALE as f64)
}

fn lookup_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn is_usd_quoted_symbol(symbol: &str) -> bool {
    let symbol = symbol.to_ascii_uppercase();
    symbol.ends_with("USDT")
        || symbol.ends_with("USDC")
        || symbol.ends_with("BUSD")
        || symbol.ends_with("FDUSD")
}

fn endpoint_pattern_matches(pattern: &str, method: &Method, path: &str) -> bool {
    let mut parts = pattern.splitn(2, ' ');
    let Some(pattern_method) = parts.next() else {
        return false;
    };
    let Some(pattern_path) = parts.next() else {
        return false;
    };

    if !pattern_method.trim().eq_ignore_ascii_case(method.as_str()) {
        return false;
    }
    wildcard_path_match(pattern_path.trim(), path)
}

fn wildcard_path_match(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let chunks: Vec<&str> = pattern.split('*').filter(|p| !p.is_empty()).collect();
    if chunks.is_empty() {
        return pattern == path;
    }

    let mut cursor = 0usize;
    let mut chunk_idx = 0usize;

    if !pattern.starts_with('*') {
        let first = chunks[0];
        if !path.starts_with(first) {
            return false;
        }
        cursor = first.len();
        chunk_idx = 1;
    }

    while chunk_idx < chunks.len() {
        let chunk = chunks[chunk_idx];
        if let Some(found) = path[cursor..].find(chunk) {
            cursor += found + chunk.len();
            chunk_idx += 1;
        } else {
            return false;
        }
    }

    if !pattern.ends_with('*')
        && let Some(last) = chunks.last()
    {
        return path.ends_with(last);
    }

    true
}

async fn load_binance_credentials(
    state: &AppState,
) -> Result<(DecryptedCredential, DecryptedCredential), Response> {
    let api_key = match state
        .credential_store
        .decrypt_for_service_and_name("binance", "api_key")
        .await
    {
        Ok(found) => found,
        Err(e) => {
            eprintln!("[fishnet] failed to read binance api key credential: {e}");
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to access credential vault",
            ));
        }
    };

    let api_secret = match state
        .credential_store
        .decrypt_for_service_and_name("binance", "api_secret")
        .await
    {
        Ok(found) => found,
        Err(e) => {
            eprintln!("[fishnet] failed to read binance api secret credential: {e}");
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to access credential vault",
            ));
        }
    };

    let Some(api_key) = api_key else {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "credential not found for service: binance (expected name=api_key)",
        ));
    };
    let Some(api_secret) = api_secret else {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            "credential not found for service: binance (expected name=api_secret)",
        ));
    };

    Ok((api_key, api_secret))
}

async fn load_custom_credential(
    state: &AppState,
    service_name: &str,
) -> Result<Option<DecryptedCredential>, Response> {
    let namespaced = format!("custom.{service_name}");
    match state
        .credential_store
        .decrypt_for_service(&namespaced)
        .await
    {
        Ok(found) => Ok(found),
        Err(e) => {
            eprintln!("[fishnet] failed to decrypt custom credential for {service_name}: {e}");
            Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to access credential vault",
            ))
        }
    }
}

fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> Result<String, String> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| "invalid HMAC key length".to_string())?;
    mac.update(message);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

async fn send_upstream(
    state: &AppState,
    method: Method,
    headers: &HeaderMap,
    target_url: &str,
    body: Option<axum::body::Bytes>,
    skip_headers: &[String],
    extra_headers: &[(String, HeaderValue)],
) -> Result<reqwest::Response, Response> {
    let mut upstream_req = state.http_client.request(method, target_url);

    for (name, value) in headers {
        if should_skip_header(name.as_str(), skip_headers) {
            continue;
        }
        upstream_req = upstream_req.header(name.clone(), value.clone());
    }

    for (name, value) in extra_headers {
        upstream_req = upstream_req.header(name, value.clone());
    }

    if let Some(body) = body
        && !body.is_empty()
    {
        upstream_req = upstream_req.body(body);
    }

    match upstream_req.send().await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            eprintln!("[fishnet] upstream request failed: {e}");
            Err(json_error(
                StatusCode::BAD_GATEWAY,
                "upstream provider is unavailable",
            ))
        }
    }
}

fn should_skip_header(name: &str, extra_skip: &[String]) -> bool {
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "host" | "transfer-encoding" | "connection" | "keep-alive" | "content-length"
    ) {
        return true;
    }

    extra_skip.iter().any(|h| h == &name)
}

fn build_proxy_response(upstream_resp: reqwest::Response) -> Response {
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
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal proxy error")
        }
    }
}

fn with_query(base: &str, path: &str, query: Option<&str>) -> String {
    match query {
        Some(query) if !query.is_empty() => format!("{base}{path}?{query}"),
        _ => format!("{base}{path}"),
    }
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_path_match_cases() {
        assert!(wildcard_path_match("/repos/*", "/repos/fishnet"));
        assert!(wildcard_path_match(
            "/repos/*/admin/*",
            "/repos/org/admin/teams"
        ));
        assert!(!wildcard_path_match("/repos/*", "/orgs/openai"));
        assert!(wildcard_path_match("*", "/anything"));
    }

    #[test]
    fn endpoint_pattern_matching_checks_method() {
        assert!(endpoint_pattern_matches(
            "DELETE /repos/*",
            &Method::DELETE,
            "/repos/fishnet"
        ));
        assert!(!endpoint_pattern_matches(
            "DELETE /repos/*",
            &Method::GET,
            "/repos/fishnet"
        ));
    }

    #[test]
    fn parse_binance_value_from_quote_qty() {
        let params = vec![
            ("symbol".to_string(), "BTCUSDT".to_string()),
            ("quoteOrderQty".to_string(), "125.5".to_string()),
        ];
        let value = parse_binance_order_value_usd(&params).unwrap();
        assert_eq!(value, 125_500_000);
    }

    #[test]
    fn parse_binance_value_from_price_times_qty() {
        let params = vec![
            ("symbol".to_string(), "ETHUSDC".to_string()),
            ("price".to_string(), "2000".to_string()),
            ("quantity".to_string(), "0.1".to_string()),
        ];
        let value = parse_binance_order_value_usd(&params).unwrap();
        assert_eq!(value, 200_000_000);
    }

    #[test]
    fn parse_binance_value_rounds_up_to_micros_for_policy_safety() {
        let params = vec![
            ("symbol".to_string(), "BTCUSDT".to_string()),
            ("quoteOrderQty".to_string(), "0.0000001".to_string()),
        ];
        let value = parse_binance_order_value_usd(&params).unwrap();
        assert_eq!(value, 1);
    }

    #[test]
    fn content_length_header_is_always_skipped() {
        assert!(should_skip_header("content-length", &[]));
    }
}
