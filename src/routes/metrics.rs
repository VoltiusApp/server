use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    Extension,
};
use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;

pub async fn get_metrics(
    State(pool): State<PgPool>,
    Extension(handle): Extension<PrometheusHandle>,
) -> impl IntoResponse {
    let size = pool.size() as f64;
    let idle = pool.num_idle() as f64;
    metrics::gauge!("voltius_db_pool_connections", "state" => "in_use").set(size - idle);
    metrics::gauge!("voltius_db_pool_connections", "state" => "idle").set(idle);

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        handle.render(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{env_lock, EnvLockGuard};
    use axum::{body::Body, http::Request, middleware::from_fn, routing::get, Router};
    use tower::ServiceExt;

    fn app(pool: PgPool) -> Router {
        Router::new()
            .route("/metrics", get(get_metrics))
            .layer(from_fn(crate::auth::require_admin_key))
            .layer(Extension(crate::observability::test_handle()))
            .with_state(pool)
    }

    #[tokio::test]
    async fn rejects_without_the_admin_key() {
        let _guard = EnvLockGuard(env_lock());
        std::env::set_var("ADMIN_SECRET", "sekret");
        let app = app(crate::test_support::dead_pool().await);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unavailable_when_no_admin_secret_is_configured() {
        let _guard = EnvLockGuard(env_lock());
        std::env::remove_var("ADMIN_SECRET");
        let app = app(crate::test_support::dead_pool().await);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("x-admin-key", "anything")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn renders_exposition_with_the_admin_key() {
        let _guard = EnvLockGuard(env_lock());
        std::env::set_var("ADMIN_SECRET", "sekret");
        let pool = crate::test_pool_or_skip!();
        let app = app(pool);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("x-admin-key", "sekret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4"
        );

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(
            body.contains("voltius_db_pool_connections"),
            "pool gauge missing from:\n{body}"
        );
        assert!(
            body.contains("state=\"in_use\""),
            "in_use label missing from:\n{body}"
        );
        assert!(
            body.contains("state=\"idle\""),
            "idle label missing from:\n{body}"
        );
        assert!(
            body.contains("voltius_build_info"),
            "build info missing from:\n{body}"
        );
    }
}
