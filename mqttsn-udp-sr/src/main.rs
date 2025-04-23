use affinity;
use dashmap::DashMap;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashSet,
    net::{SocketAddr, UdpSocket},
    str,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

type Topic = String;
type SubscriberSet = HashSet<SocketAddr>;

fn create_reuse_socket() -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    
    let addr = "0.0.0.0:11211".parse::<SocketAddr>().unwrap();
    socket.bind(&addr.into())?;
    
    Ok(UdpSocket::from(socket))
}

fn main() -> std::io::Result<()> {
    let topics: Arc<DashMap<Topic, SubscriberSet>> = Arc::new(DashMap::new());
    let publish_counter = Arc::new(AtomicUsize::new(0));
    let clone_counter = Arc::new(AtomicUsize::new(0));
    let core_counters: Arc<Vec<AtomicUsize>> = Arc::new((0..16).map(|_| AtomicUsize::new(0)).collect());
    let core_latencies: Arc<Vec<Mutex<Vec<u64>>>> = Arc::new((0..16).map(|_| Mutex::new(Vec::new())).collect());

    for core_id in 0..16 {
        let sock = Arc::new(create_reuse_socket()?);
        let topics = Arc::clone(&topics);
        let pub_count = Arc::clone(&publish_counter);
        let clone_count = Arc::clone(&clone_counter);
        let core_counts = Arc::clone(&core_counters);
        let latencies = Arc::clone(&core_latencies);

        thread::spawn(move || {
            affinity::set_thread_affinity([core_id]).unwrap();
            println!("[thread-{core_id}] Started and pinned");

            let mut buf = [0u8; 4096];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, addr)) => {
                        core_counts[core_id].fetch_add(1, Ordering::Relaxed);
                        let msg = String::from_utf8_lossy(&buf[..n]).to_string();
                        handle_message(
                            &msg, addr, &sock, &topics,
                            &pub_count, &clone_count,
                            core_id, &latencies,
                        );
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => {
                        eprintln!("[thread-{core_id}] recv error: {}", e);
                    }
                }
            }
        });
    }

    loop {
        thread::sleep(Duration::from_secs(5));
        let pub_total = publish_counter.load(Ordering::Relaxed);
        let clone_total = clone_counter.load(Ordering::Relaxed);

        let mut all_latencies = Vec::new();
        for mutex in core_latencies.iter() {
            let mut lat = mutex.lock().unwrap();
            // all_latencies.extend(lat.drain(..)); // Clear after collecting
            all_latencies.extend(lat.iter().copied()); 
        }

        let avg_latency = if all_latencies.is_empty() {
            0.0
        } else {
            all_latencies.iter().sum::<u64>() as f64 / all_latencies.len() as f64
        };

        println!(
            "[stats] Received PUBLISH: {}, Cloned to subscribers: {}, QPS: {}",
            pub_total, clone_total, pub_total / 30
        );
        println!("[latency] data_points: {}, avg: {} ns", all_latencies.len(), avg_latency);
        println!("");
    }
}

fn handle_message(
    msg: &str,
    sender: SocketAddr,
    sock: &UdpSocket,
    topics: &DashMap<Topic, SubscriberSet>,
    publish_counter: &AtomicUsize,
    clone_counter: &AtomicUsize,
    core_id: usize,
    core_latencies: &Arc<Vec<Mutex<Vec<u64>>>>,
) {
    let mut parts = msg.trim().splitn(3, ' ');
    match parts.next() {
        Some("REGISTER") => {
            if let Some(topic) = parts.next() {
                topics.entry(topic.to_string()).or_insert(HashSet::new());
                println!("[register] Topic '{}' created", topic);
                let _ = sock.send_to(b"REGACK", sender);
            }
        }
        Some("SUBSCRIBE") => {
            if let Some(topic) = parts.next() {
                let mut set = topics.entry(topic.to_string()).or_insert(HashSet::new());
                set.insert(sender);
                println!("[subscribe] {} subscribed to '{}'", sender, topic);
                let _ = sock.send_to(b"SUBACK", sender);
            }
        }
        Some("PUBLISH") => {
            if let (Some(topic), Some(payload)) = (parts.next(), parts.next()) {
                let start = Instant::now();
                publish_counter.fetch_add(1, Ordering::Relaxed);

                if let Some(subs) = topics.get(topic) {
                    for sub in subs.iter() {
                        let _ = sock.send_to(payload.as_bytes(), *sub);
                        clone_counter.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    println!("[publish] No topic '{}' registered", topic);
                }

                let latency_ns = start.elapsed().as_nanos() as u64;
                let mut vec = core_latencies[core_id].lock().unwrap();
                vec.push(latency_ns);
            }
        }
        _ => {
            println!("[!] Unknown command from {}: {}", sender, msg);
        }
    }
}
