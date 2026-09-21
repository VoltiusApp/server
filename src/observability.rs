use axum::{
    extract::MatchedPath, extract::Request, http::Method, middleware::Next, response::Response,
};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::time::{Duration, Instant};

const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

pub fn init() -> PrometheusHandle {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("voltius_http_request_duration_seconds".to_string()),
            DURATION_BUCKETS,
        )
        .expect("configure duration buckets")
        .install_recorder()
        .expect("install prometheus recorder");

    // The exporter does no upkeep of its own; without this the histograms grow unboundedly.
    let upkeep = handle.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            upkeep.run_upkeep();
        }
    });

    metrics::gauge!(
        "voltius_build_info",
        "version" => env!("CARGO_PKG_VERSION"),
        "sha" => option_env!("GIT_SHA").unwrap_or("unknown"),
    )
    .set(1.0);

    handle
}

pub async fn refresh_storage_gauge(pool: &sqlx::PgPool) {
    match sqlx::query_scalar::<_, i64>("SELECT pg_total_relation_size('sync_blobs')")
        .fetch_one(pool)
        .await
    {
        Ok(bytes) => metrics::gauge!("voltius_sync_blobs_bytes").set(bytes as f64),
        Err(e) => tracing::error!(error = %e, "sync_blobs size query failed"),
    }
}

pub fn spawn_storage_refresher(pool: sqlx::PgPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            refresh_storage_gauge(&pool).await;
        }
    });
}

#[cfg(test)]
pub(crate) fn test_handle() -> PrometheusHandle {
    // install_recorder succeeds once per process, so every test shares this one.
    static HANDLE: std::sync::OnceLock<PrometheusHandle> = std::sync::OnceLock::new();
    HANDLE.get_or_init(init).clone()
}

fn path_label(req: &Request) -> String {
    // The URI carries user and object ids; labelling with it makes the series count
    // grow with the number of rows rather than the number of routes.
    req.extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "<unmatched>".to_string())
}

// A client-supplied HTTP method is an arbitrary token (extension methods), never
// evicted from the registry; anything outside the known verbs collapses to one label.
fn method_label(method: &Method) -> &'static str {
    match method.as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "DELETE" => "DELETE",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        "CONNECT" => "CONNECT",
        "TRACE" => "TRACE",
        _ => "<other>",
    }
}

pub async fn track_requests(req: Request, next: Next) -> Response {
    let method = method_label(req.method());
    let path = path_label(&req);
    let started = Instant::now();

    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();

    metrics::counter!(
        "voltius_http_requests_total",
        "method" => method,
        "path" => path.clone(),
        "status" => status,
    )
    .increment(1);
    metrics::histogram!(
        "voltius_http_request_duration_seconds",
        "method" => method,
        "path" => path,
    )
    .record(started.elapsed().as_secs_f64());

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, middleware::from_fn, routing::get, Router};
    use tower::ServiceExt;

    async fn ok_handler() -> &'static str {
        "ok"
    }

    #[tokio::test]
    async fn records_the_route_pattern_not_the_uri() {
        let h = test_handle();
        let app = Router::new()
            .route("/t1/:id", get(ok_handler))
            .layer(from_fn(track_requests));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/t1/6f1a0b2c-dead-beef-0000-000000000001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        h.run_upkeep();
        let rendered = h.render();
        assert!(
            rendered.contains("path=\"/t1/:id\""),
            "route pattern missing from:\n{rendered}"
        );
        assert!(
            !rendered.contains("6f1a0b2c-dead-beef"),
            "request URI leaked into a label:\n{rendered}"
        );
    }

    #[tokio::test]
    async fn records_unmatched_requests_under_a_single_label() {
        let h = test_handle();
        let app = Router::new()
            .route("/t2", get(ok_handler))
            .layer(from_fn(track_requests));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/t2/nope/not/a/route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);

        h.run_upkeep();
        let rendered = h.render();
        assert!(
            rendered.contains("path=\"<unmatched>\""),
            "unmatched label missing from:\n{rendered}"
        );
        assert!(
            !rendered.contains("not/a/route"),
            "unmatched URI leaked into a label:\n{rendered}"
        );
    }

    #[tokio::test]
    async fn records_status_and_duration() {
        let h = test_handle();
        let app = Router::new()
            .route("/t3", get(|| async { axum::http::StatusCode::IM_A_TEAPOT }))
            .layer(from_fn(track_requests));

        app.oneshot(Request::builder().uri("/t3").body(Body::empty()).unwrap())
            .await
            .unwrap();

        h.run_upkeep();
        let rendered = h.render();
        assert!(
            rendered.contains("voltius_http_requests_total"),
            "counter missing from:\n{rendered}"
        );
        assert!(
            rendered.contains("status=\"418\""),
            "status label missing from:\n{rendered}"
        );
        assert!(
            rendered.contains("voltius_http_request_duration_seconds_bucket"),
            "histogram missing from:\n{rendered}"
        );
        assert!(
            rendered.contains("le=\"0.025\""),
            "configured buckets missing from:\n{rendered}"
        );
    }

    #[tokio::test]
    async fn records_extension_methods_under_other_not_the_raw_token() {
        let h = test_handle();
        let app = Router::new()
            .route("/t4", axum::routing::any(ok_handler))
            .layer(from_fn(track_requests));

        let resp = app
            .oneshot(
                Request::builder()
                    .method("XCUSTOMVERB")
                    .uri("/t4")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        h.run_upkeep();
        let rendered = h.render();
        assert!(
            rendered.contains("method=\"<other>\""),
            "extension method not collapsed to <other>:\n{rendered}"
        );
        assert!(
            !rendered.contains("XCUSTOMVERB"),
            "raw extension method token leaked into a label:\n{rendered}"
        );
    }

    #[tokio::test]
    async fn storage_gauge_reports_the_sync_blobs_size() {
        let h = test_handle();
        let pool = crate::test_pool_or_skip!();

        refresh_storage_gauge(&pool).await;

        h.run_upkeep();
        let rendered = h.render();
        assert!(
            rendered.contains("voltius_sync_blobs_bytes"),
            "storage gauge missing from:\n{rendered}"
        );
    }
}
