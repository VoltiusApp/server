use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use sqlx::PgPool;

pub async fn health() -> &'static str {
    "ok"
}

pub async fn health_deep(State(pool): State<PgPool>) -> Response {
    let size = pool.size();
    let idle = pool.num_idle();

    match sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&pool).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "database": "ok", "pool_size": size, "pool_idle": idle })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "deep health check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "database": "unreachable", "pool_size": size, "pool_idle": idle })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::get, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_is_static_and_does_not_touch_the_database() {
        let app = Router::new().route("/health", get(health));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"ok");
    }

    #[tokio::test]
    async fn health_deep_reports_ok_against_a_live_pool() {
        let pool = crate::test_pool_or_skip!();
        let app = Router::new()
            .route("/health/deep", get(health_deep))
            .with_state(pool);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health/deep")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["database"], "ok");
        assert!(body["pool_size"].is_number());
        assert!(body["pool_idle"].is_number());
    }

    #[tokio::test]
    async fn health_deep_reports_503_when_the_database_is_unreachable() {
        let pool = crate::test_support::dead_pool().await;
        let app = Router::new()
            .route("/health/deep", get(health_deep))
            .with_state(pool);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health/deep")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["database"], "unreachable");
    }
}
