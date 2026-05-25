use affinity;
use dashmap::DashMap;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashSet,
    net::{SocketAddr, UdpSocket},
    str,
    sync::{
        atomic::{AtomicUsize, Ordering}, Arc,
    },
    thread,
    time::Duration,
};

type Topic = String;
type SubscriberSet = HashSet<SocketAddr>;

fn create_reuse_socket(port: u16) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_port(true)?;
    
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    socket.bind(&addr.into())?;
    
    Ok(UdpSocket::from(socket))
}


fn main() -> std::io::Result<()> {
    let topics: Arc<DashMap<Topic, SubscriberSet>> = Arc::new(DashMap::new());
    let publish_counter = Arc::new(AtomicUsize::new(0));
    let clone_counter = Arc::new(AtomicUsize::new(0));
    let core_counters: Arc<Vec<AtomicUsize>> = Arc::new((0..16).map(|_| AtomicUsize::new(0)).collect());
    // let core_latencies: Arc<Vec<Mutex<Vec<u64>>>> = Arc::new((0..16).map(|_| Mutex::new(Vec::new())).collect());

    let base_port = 49152;

    // for core_id in 0..16 {
    for core_id in 0..1 {
        let port = base_port + core_id;
        let sock = Arc::new(create_reuse_socket(port)?);
        let topics = Arc::clone(&topics);
        let pub_count = Arc::clone(&publish_counter);
        let clone_count = Arc::clone(&clone_counter);
        let core_counts = Arc::clone(&core_counters);

        thread::spawn(move || {
            affinity::set_thread_affinity(&[core_id as usize]).unwrap();

            println!("[thread-{core_id}] Listening on port {port} and pinned");

            let mut buf = [0u8; 4096];
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, addr)) => {
                        core_counts[core_id as usize].fetch_add(1, Ordering::Relaxed);
                        let msg = String::from_utf8_lossy(&buf[..n]).to_string();
                        handle_message(
                            &msg, addr, &sock, &topics,
                            &pub_count, &clone_count,
                            core_id as usize
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

        for (core_id, count) in core_counters.iter().enumerate() {
            println!("[thread-{core_id}] count: {}", count.load(Ordering::Relaxed));
        }

        // let mut all_latencies = Vec::new();
        // for mutex in core_latencies.iter() {
        //     let mut lat = mutex.lock().unwrap();
        //     // all_latencies.extend(lat.drain(..)); // Clear after collecting
        //     all_latencies.extend(lat.iter().copied()); 
        // }

        // let avg_latency = if all_latencies.is_empty() {
        //     0.0
        // } else {
        //     all_latencies.iter().sum::<u64>() as f64 / all_latencies.len() as f64
        // };

        println!(
            "[stats] Received PUBLISH: {}, Cloned to subscribers: {}, QPS: {}",
            pub_total, clone_total, pub_total / 30
        );
        // println!("[latency] data_points: {}, avg: {} ns", all_latencies.len(), avg_latency);
        // println!("");
    }
}

fn handle_message(
    msg: &str,
    sender: SocketAddr,
    sock: &UdpSocket,
    topics: &DashMap<Topic, SubscriberSet>,
    publish_counter: &AtomicUsize,
    clone_counter: &AtomicUsize,
    _core_id: usize,
    // core_latencies: &Arc<Vec<Mutex<Vec<u64>>>>,
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
            if let (Some(topic), Some(rest)) = (parts.next(), parts.next()) {
                let raw_payload = format!("PUBLISH {} {}", topic, rest);
                publish_counter.fetch_add(1, Ordering::Relaxed);

                if let Some(subs) = topics.get(topic) {
                    for sub in subs.iter() {
                        // println!("[publish] Sending to {} with payload {} ", sub, raw_payload);
                        if let Err(e) = sock.send_to(raw_payload.as_bytes(), *sub) {
                            eprintln!("[publish] Failed to send to {}: {}", sub, e);
                        }
                        clone_counter.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    println!("[publish] No topic '{}' registered", topic);
                }
            }
        }
        Some("FLUSH") => {
            if let Some(topic) = parts.next() {
                if let Some(mut subs) = topics.get_mut(topic) {
                    let count = subs.len();
                    subs.clear();
                    println!("[flush] Topic '{}': cleared {} subscribers", topic, count);
                } else {
                    println!("[flush] Topic '{}': not found", topic);
                }
                let _ = sock.send_to(b"FLUSHED", sender);
            }
        }
        _ => {
            println!("[!] Unknown command from {}: {}", sender, msg);
        }
    }
}
