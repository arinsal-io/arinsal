use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::sync::{broadcast, mpsc};

fn fib(n: u64) -> u64 {
    if n < 2 { n } else { fib(n - 1) + fib(n - 2) }
}
struct Node {
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}
fn mk(d: u32) -> Box<Node> {
    if d == 0 {
        Box::new(Node {
            left: None,
            right: None,
        })
    } else {
        Box::new(Node {
            left: Some(mk(d - 1)),
            right: Some(mk(d - 1)),
        })
    }
}
fn check(n: &Node) -> u64 {
    match (&n.left, &n.right) {
        (Some(l), Some(r)) => 1 + check(l) + check(r),
        _ => 1,
    }
}
fn trees(max: u32) -> u64 {
    let mut sum = 0;
    for d in (4..=max).step_by(2) {
        for _ in 0..(1_u64 << (max - d + 4)) {
            sum += check(&mk(d));
        }
    }
    sum
}
fn nbody(n: usize) -> f64 {
    let mut b: [[f64; 7]; 5] = [
        [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 39.47],
        [4.84, -1.16, -0.10, 0.60, 2.81, -0.02, 0.037],
        [8.34, 4.12, -0.4, -1.01, 1.82, 0.008, 0.011],
        [12.89, -15.11, -0.22, 1.08, 0.86, -0.01, 0.0017],
        [15.37, -25.9, 0.17, 0.97, 0.59, -0.03, 0.002],
    ];
    for _ in 0..n {
        for i in 0..5 {
            for j in i + 1..5 {
                let dx = b[i][0] - b[j][0];
                let dy = b[i][1] - b[j][1];
                let dz = b[i][2] - b[j][2];
                let d2 = dx * dx + dy * dy + dz * dz;
                let mag = 0.01 / (d2 * d2.sqrt());
                let (mi, mj) = (b[i][6], b[j][6]);
                b[i][3] -= dx * mj * mag;
                b[i][4] -= dy * mj * mag;
                b[i][5] -= dz * mj * mag;
                b[j][3] += dx * mi * mag;
                b[j][4] += dy * mi * mag;
                b[j][5] += dz * mi * mag;
            }
        }
        for body in &mut b {
            body[0] += 0.01 * body[3];
            body[1] += 0.01 * body[4];
            body[2] += 0.01 * body[5];
        }
    }
    b[0][0]
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime")
}
fn tasks(n: usize) -> usize {
    runtime().block_on(async move {
        let (tx, _) = broadcast::channel::<()>(1);
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let mut rx = tx.subscribe();
            handles.push(tokio::spawn(async move {
                let _ = rx.recv().await;
            }));
        }
        let _ = tx.send(());
        for handle in handles {
            handle.await.expect("task");
        }
        n
    })
}
fn ring(n: usize, m: usize) -> usize {
    runtime().block_on(async move {
        let mut senders = Vec::with_capacity(n);
        let mut receivers = Vec::with_capacity(n);
        for _ in 0..n {
            let (tx, rx) = mpsc::unbounded_channel::<usize>();
            senders.push(tx);
            receivers.push(rx);
        }
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<()>();
        let mut handles = Vec::with_capacity(n);
        for (i, mut rx) in receivers.into_iter().enumerate() {
            let next = senders[(i + 1) % n].clone();
            let done = done_tx.clone();
            handles.push(tokio::spawn(async move {
                while let Some(value) = rx.recv().await {
                    if value == 0 {
                        break;
                    }
                    if value == 1 {
                        done.send(()).expect("ring done");
                    } else {
                        next.send(value - 1).expect("ring next");
                    }
                }
            }));
        }
        senders[0].send(m).expect("ring start");
        done_rx.recv().await.expect("ring result");
        for tx in &senders {
            tx.send(0).expect("ring stop");
        }
        for handle in handles {
            handle.await.expect("ring worker");
        }
        m
    })
}
fn pingpong(n: usize) -> usize {
    runtime().block_on(async move {
        let (ping_tx, mut ping_rx) = mpsc::channel::<()>(1);
        let (pong_tx, mut pong_rx) = mpsc::channel::<()>(1);
        let peer = tokio::spawn(async move {
            while ping_rx.recv().await.is_some() {
                pong_tx.send(()).await.expect("pong");
            }
        });
        for _ in 0..n {
            ping_tx.send(()).await.expect("ping");
            pong_rx.recv().await.expect("pong result");
        }
        drop(ping_tx);
        peer.await.expect("peer");
        n
    })
}
enum Message {
    Binary(Arc<Vec<u8>>),
    List(Vec<u64>),
}
fn bigmsg(n: usize) -> usize {
    runtime().block_on(async move {
        let binary = Arc::new(vec![7_u8; 1048576]);
        let list = vec![7_u64; 65536];
        let (tx, mut rx) = mpsc::channel::<Message>(1);
        let (ack_tx, mut ack_rx) = mpsc::channel::<usize>(1);
        let peer = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                let size = match message {
                    Message::Binary(data) => data.len(),
                    Message::List(data) => data.iter().map(|value| *value as usize).sum(),
                };
                ack_tx.send(size).await.expect("ack");
            }
        });
        for _ in 0..n {
            tx.send(Message::Binary(binary.clone()))
                .await
                .expect("binary");
            assert_eq!(ack_rx.recv().await, Some(1048576));
            tx.send(Message::List(list.clone())).await.expect("list");
            assert_eq!(ack_rx.recv().await, Some(458752));
        }
        drop(tx);
        peer.await.expect("peer");
        n * (1048576 + 458752)
    })
}
fn map_update(n: usize, size: usize) -> usize {
    let mut map: HashMap<usize, usize> = (0..size).map(|i| (i, 0)).collect();
    for i in 0..n {
        map.insert(i % size, i + 1);
    }
    map.len() + map[&((n - 1) % size)]
}
fn binary_parse(megabytes: usize) -> usize {
    let mut frame = vec![0_u8; 1028];
    frame[..4].copy_from_slice(&1024_u32.to_be_bytes());
    frame[4] = 7;
    frame[1027] = 9;
    let stream = frame.repeat(megabytes * 1024);
    let mut rest = stream.as_slice();
    let mut sum = 0;
    while !rest.is_empty() {
        let len = u32::from_be_bytes(rest[..4].try_into().expect("length")) as usize;
        let payload = &rest[4..4 + len];
        sum += len + payload.iter().map(|byte| *byte as usize).sum::<usize>();
        rest = &rest[4 + len..];
    }
    sum
}
fn ets(n: usize) -> usize {
    let table = Arc::new(RwLock::new(
        (0..1000)
            .map(|key| (key, 0))
            .collect::<HashMap<usize, usize>>(),
    ));
    let mut handles = Vec::new();
    for worker in 0..4 {
        let table = table.clone();
        handles.push(std::thread::spawn(move || {
            let mut sum = 0;
            for i in 0..n / 4 {
                let key = (i * 4 + worker) % 1000;
                if i % 4 == 0 {
                    table.write().expect("write lock").insert(key, i);
                } else {
                    assert!(table.read().expect("read lock").contains_key(&key));
                }
                sum += 1;
            }
            sum
        }));
    }
    handles
        .into_iter()
        .map(|handle| handle.join().expect("worker"))
        .sum()
}
fn fanin(n: usize) -> usize {
    runtime().block_on(async move {
        let (tx, mut rx) = mpsc::channel::<usize>(1024);
        let mut handles = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let tx = tx.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..n / 1000 {
                    tx.send(1).await.expect("send");
                }
            }));
        }
        drop(tx);
        let mut sum = 0;
        while let Some(value) = rx.recv().await {
            sum += value;
        }
        for handle in handles {
            handle.await.expect("producer");
        }
        sum
    })
}
fn fanout(n: usize) -> usize {
    runtime().block_on(async move {
        let mut senders = Vec::with_capacity(1000);
        let mut handles = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let (tx, mut rx) = mpsc::channel::<usize>(1);
            senders.push(tx);
            handles.push(tokio::spawn(async move {
                let mut sum = 0;
                while let Some(value) = rx.recv().await {
                    sum += value;
                }
                sum
            }));
        }
        for _ in 0..n / 1000 {
            for tx in &senders {
                tx.send(1).await.expect("fanout send");
            }
        }
        drop(senders);
        let mut sum = 0;
        for handle in handles {
            sum += handle.await.expect("consumer");
        }
        sum
    })
}
fn forward(n: usize) -> usize {
    runtime().block_on(async move {
        let list = Arc::new(vec![7_u64; 65536]);
        let (first_tx, mut rx) = mpsc::channel::<Arc<Vec<u64>>>(1);
        for _ in 0..9 {
            let (tx, next_rx) = mpsc::channel::<Arc<Vec<u64>>>(1);
            let mut hop_rx = rx;
            tokio::spawn(async move {
                while let Some(v) = hop_rx.recv().await {
                    tx.send(v).await.expect("hop");
                }
            });
            rx = next_rx;
        }
        let (ack_tx, mut ack_rx) = mpsc::channel::<u64>(1);
        let mut last_rx = rx;
        tokio::spawn(async move {
            while let Some(v) = last_rx.recv().await {
                ack_tx.send(v.iter().sum()).await.expect("ack");
            }
        });
        for _ in 0..n {
            first_tx.send(list.clone()).await.expect("send");
            assert_eq!(ack_rx.recv().await, Some(458752));
        }
        n * 458752
    })
}

fn broadcast(n: usize) -> usize {
    runtime().block_on(async move {
        let list = Arc::new(vec![7_u64; 65536]);
        let (ack_tx, mut ack_rx) = mpsc::channel::<u64>(1000);
        let mut senders = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let (tx, mut rx) = mpsc::channel::<Arc<Vec<u64>>>(1);
            let ack_tx = ack_tx.clone();
            tokio::spawn(async move {
                while let Some(v) = rx.recv().await {
                    ack_tx.send(v[0]).await.expect("ack");
                }
            });
            senders.push(tx);
        }
        for _ in 0..n {
            for tx in &senders {
                tx.send(list.clone()).await.expect("send");
            }
            for _ in 0..1000 {
                assert_eq!(ack_rx.recv().await, Some(7));
            }
        }
        n * 1000 * 7
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.len() >= 3, "usage: bench NAME N [M]");
    let name = args[1].as_str();
    let n: usize = args[2].parse().expect("integer argument");
    let start = Instant::now();
    let result = match name {
        "fib" => fib(n as u64).to_string(),
        "trees" => trees(n as u32).to_string(),
        "nbody" => nbody(n).to_string(),
        "idle" => "0".to_string(),
        "tasks" => tasks(n).to_string(),
        "ring" => ring(n, args[3].parse().expect("ring hops")).to_string(),
        "pingpong" => pingpong(n).to_string(),
        "bigmsg" => bigmsg(n).to_string(),
        "map_update" => map_update(n, 1000).to_string(),
        "map_update_small" => map_update(n, 32).to_string(),
        "binary_parse" => binary_parse(n).to_string(),
        "ets" => ets(n).to_string(),
        "fanin" => fanin(n).to_string(),
        "fanout" => fanout(n).to_string(),
        "forward" => forward(n).to_string(),
        "broadcast" => broadcast(n).to_string(),
        _ => panic!("unknown benchmark"),
    };
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("{result}");
    println!("{name} {elapsed_ms:.3}ms");
}
