use axum::{
    Json, Router,
    extract::Query,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Serialize)]
struct Item {
    id: usize,
    name: String,
    score: JsonScore,
}

struct JsonScore(f64);

impl Serialize for JsonScore {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0.fract() == 0.0 {
            serializer.serialize_i64(self.0 as i64)
        } else {
            serializer.serialize_f64(self.0)
        }
    }
}

#[derive(Deserialize)]
struct WorkQuery {
    n: Option<usize>,
}

fn fib(n: usize) -> String {
    // Decimal digits keep the JSON integer exact through the n=1000 cap.
    let (mut a, mut b) = (vec![0_u8], vec![1_u8]);
    for _ in 0..n {
        let mut sum = vec![0_u8; a.len().max(b.len())];
        let mut carry = 0;
        for (index, digit) in sum.iter_mut().enumerate() {
            let value =
                a.get(index).copied().unwrap_or(0) + b.get(index).copied().unwrap_or(0) + carry;
            *digit = value % 10;
            carry = value / 10;
        }
        if carry != 0 {
            sum.push(carry);
        }
        (a, b) = (b, sum);
    }
    a.iter()
        .rev()
        .map(|digit| char::from(b'0' + *digit))
        .collect()
}

async fn work(
    Query(query): Query<WorkQuery>,
) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    let n = query.n.unwrap_or(20).min(1000);
    let items: Vec<Item> = (0..n)
        .map(|id| Item {
            id,
            name: format!("item-{id}"),
            score: JsonScore(id as f64 * 1.5),
        })
        .collect();
    let item_json = serde_json::to_string(&items).expect("serialize work items");
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        format!("{{\"n\":{n},\"fib\":{},\"items\":{item_json}}}", fib(n)),
    )
}

async fn echo(Json(value): Json<Value>) -> (StatusCode, Json<Value>) {
    let canonical = match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        other => other,
    };
    (StatusCode::OK, Json(canonical))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8082".to_owned());
    let app = Router::new()
        .route(
            "/plaintext",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "text/plain")],
                    "Hello, World!",
                )
            }),
        )
        .route(
            "/json",
            get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    r#"{"message":"Hello, World!"}"#,
                )
            }),
        )
        .route("/work", get(work))
        .route("/echo", post(echo));
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("bind HTTP listener");
    axum::serve(listener, app)
        .await
        .expect("serve HTTP requests");
}
