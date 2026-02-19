use std::path::PathBuf;
use std::sync::Mutex;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::constants;
use crate::state::AppState;

pub struct SpendStore {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpendRecord {
    pub service: String,
    pub date: String,
    pub cost_usd: f64,
    pub request_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceBudget {
    pub service: String,
    pub daily_budget_usd: f64,
    pub monthly_budget_usd: Option<f64>,
    pub updated_at: i64,
}

impl SpendStore {
    pub fn open(path: PathBuf) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(&path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS spend_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                date TEXT NOT NULL,
                cost_usd REAL NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_spend_service_date
                ON spend_records(service, date);

            CREATE TABLE IF NOT EXISTS service_budgets (
                service TEXT PRIMARY KEY,
                daily_budget_usd REAL NOT NULL,
                monthly_budget_usd REAL,
                updated_at INTEGER NOT NULL
            );",
        )?;
        Ok(())
    }

    pub fn record_spend(
        &self,
        service: &str,
        date: &str,
        cost_usd: f64,
    ) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO spend_records (service, date, cost_usd, request_count, created_at)
             VALUES (?1, ?2, ?3, 1, ?4)",
            params![service, date, cost_usd, now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn query_spend(&self, days: u32) -> Result<Vec<SpendRecord>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let cutoff = chrono::Utc::now()
            .date_naive()
            .checked_sub_days(chrono::Days::new(days as u64))
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default();

        let mut stmt = conn.prepare(
            "SELECT service, date, SUM(cost_usd) as total_cost, SUM(request_count) as total_requests
             FROM spend_records
             WHERE date >= ?1
             GROUP BY service, date
             ORDER BY date DESC, service ASC",
        )?;

        let rows = stmt.query_map(params![cutoff], |row| {
            Ok(SpendRecord {
                service: row.get(0)?,
                date: row.get(1)?,
                cost_usd: row.get(2)?,
                request_count: row.get(3)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn get_spent_today(&self, service: &str) -> Result<f64, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let spent: f64 = conn
            .query_row(
                "SELECT COALESCE(SUM(cost_usd), 0.0) FROM spend_records WHERE service = ?1 AND date = ?2",
                params![service, today],
                |row| row.get(0),
            )?;
        Ok(spent)
    }

    pub fn set_budget(&self, budget: &ServiceBudget) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO service_budgets (service, daily_budget_usd, monthly_budget_usd, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(service) DO UPDATE SET
                daily_budget_usd = excluded.daily_budget_usd,
                monthly_budget_usd = excluded.monthly_budget_usd,
                updated_at = excluded.updated_at",
            params![
                budget.service,
                budget.daily_budget_usd,
                budget.monthly_budget_usd,
                budget.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn get_budgets(&self) -> Result<Vec<ServiceBudget>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT service, daily_budget_usd, monthly_budget_usd, updated_at FROM service_budgets",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ServiceBudget {
                service: row.get(0)?,
                daily_budget_usd: row.get(1)?,
                monthly_budget_usd: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn get_budget(&self, service: &str) -> Result<Option<ServiceBudget>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT service, daily_budget_usd, monthly_budget_usd, updated_at
             FROM service_budgets WHERE service = ?1",
        )?;
        let mut rows = stmt.query_map(params![service], |row| {
            Ok(ServiceBudget {
                service: row.get(0)?,
                daily_budget_usd: row.get(1)?,
                monthly_budget_usd: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })?;
        match rows.next() {
            Some(Ok(budget)) => Ok(Some(budget)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    pub fn default_path() -> Option<PathBuf> {
        let mut path = dirs::home_dir()?;
        path.push(constants::FISHNET_DIR);
        path.push(constants::SPEND_DB_FILE);
        Some(path)
    }
}

#[derive(Debug, Deserialize)]
pub struct SpendQuery {
    pub days: Option<u32>,
}

pub async fn get_spend(
    State(state): State<AppState>,
    Query(query): Query<SpendQuery>,
) -> impl IntoResponse {
    let config = state.config();

    if !config.llm.track_spend {
        return Json(serde_json::json!({ "enabled": false })).into_response();
    }

    let days = query
        .days
        .unwrap_or(config.dashboard.spend_history_days)
        .min(config.dashboard.spend_history_days);

    match state.spend_store.query_spend(days) {
        Ok(daily) => {
            let budgets = state.spend_store.get_budgets().unwrap_or_default();
            let mut budget_map = serde_json::Map::new();
            for b in &budgets {
                let spent_today = state
                    .spend_store
                    .get_spent_today(&b.service)
                    .unwrap_or(0.0);
                let warning_active = config.llm.budget_warning_pct > 0
                    && b.daily_budget_usd > 0.0
                    && spent_today >= b.daily_budget_usd * (config.llm.budget_warning_pct as f64 / 100.0);
                budget_map.insert(
                    b.service.clone(),
                    serde_json::json!({
                        "daily_limit": b.daily_budget_usd,
                        "spent_today": spent_today,
                        "warning_pct": config.llm.budget_warning_pct,
                        "warning_active": warning_active,
                    }),
                );
            }

            Json(serde_json::json!({
                "enabled": true,
                "config": {
                    "track_spend": config.llm.track_spend,
                    "spend_history_days": config.dashboard.spend_history_days,
                },
                "daily": daily,
                "budgets": budget_map,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("database error: {e}") })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct SetBudgetRequest {
    pub service: String,
    pub daily_budget_usd: f64,
    pub monthly_budget_usd: Option<f64>,
}

pub async fn set_budget(
    State(state): State<AppState>,
    Json(req): Json<SetBudgetRequest>,
) -> impl IntoResponse {
    let budget = ServiceBudget {
        service: req.service,
        daily_budget_usd: req.daily_budget_usd,
        monthly_budget_usd: req.monthly_budget_usd,
        updated_at: chrono::Utc::now().timestamp(),
    };
    match state.spend_store.set_budget(&budget) {
        Ok(()) => Json(serde_json::json!({ "success": true, "budget": budget })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("database error: {e}") })),
        )
            .into_response(),
    }
}

pub async fn get_budgets(State(state): State<AppState>) -> impl IntoResponse {
    match state.spend_store.get_budgets() {
        Ok(budgets) => Json(serde_json::json!({ "budgets": budgets })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("database error: {e}") })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory() {
        let store = SpendStore::open_in_memory().unwrap();
        let records = store.query_spend(30).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_record_and_query_spend() {
        let store = SpendStore::open_in_memory().unwrap();
        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        store.record_spend("openai", &today, 1.50).unwrap();
        store.record_spend("openai", &today, 2.50).unwrap();
        store.record_spend("anthropic", &today, 3.00).unwrap();

        let records = store.query_spend(30).unwrap();
        assert_eq!(records.len(), 2);

        let openai = records.iter().find(|r| r.service == "openai").unwrap();
        assert!((openai.cost_usd - 4.0).abs() < 0.001);
        assert_eq!(openai.request_count, 2);

        let anthropic = records.iter().find(|r| r.service == "anthropic").unwrap();
        assert!((anthropic.cost_usd - 3.0).abs() < 0.001);
        assert_eq!(anthropic.request_count, 1);
    }

    #[test]
    fn test_spent_today() {
        let store = SpendStore::open_in_memory().unwrap();
        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();

        assert!((store.get_spent_today("openai").unwrap() - 0.0).abs() < 0.001);

        store.record_spend("openai", &today, 5.25).unwrap();
        store.record_spend("openai", &today, 3.75).unwrap();

        assert!((store.get_spent_today("openai").unwrap() - 9.0).abs() < 0.001);
        assert!((store.get_spent_today("anthropic").unwrap() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_budget_crud() {
        let store = SpendStore::open_in_memory().unwrap();

        let budget = ServiceBudget {
            service: "openai".to_string(),
            daily_budget_usd: 20.0,
            monthly_budget_usd: Some(500.0),
            updated_at: 1000,
        };
        store.set_budget(&budget).unwrap();

        let loaded = store.get_budget("openai").unwrap().unwrap();
        assert!((loaded.daily_budget_usd - 20.0).abs() < 0.001);
        assert!((loaded.monthly_budget_usd.unwrap() - 500.0).abs() < 0.001);

        assert!(store.get_budget("anthropic").unwrap().is_none());

        let all = store.get_budgets().unwrap();
        assert_eq!(all.len(), 1);

        let updated = ServiceBudget {
            service: "openai".to_string(),
            daily_budget_usd: 30.0,
            monthly_budget_usd: None,
            updated_at: 2000,
        };
        store.set_budget(&updated).unwrap();

        let loaded = store.get_budget("openai").unwrap().unwrap();
        assert!((loaded.daily_budget_usd - 30.0).abs() < 0.001);
        assert!(loaded.monthly_budget_usd.is_none());
    }

    #[test]
    fn test_query_spend_respects_days() {
        let store = SpendStore::open_in_memory().unwrap();
        let today = chrono::Utc::now()
            .date_naive()
            .format("%Y-%m-%d")
            .to_string();
        let old_date = "2020-01-01";

        store.record_spend("openai", &today, 1.0).unwrap();
        store.record_spend("openai", old_date, 5.0).unwrap();

        let recent = store.query_spend(30).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].date, today);

        let all = store.query_spend(10000).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_migration_idempotent() {
        let store = SpendStore::open_in_memory().unwrap();
        store.migrate().unwrap();
    }
}
