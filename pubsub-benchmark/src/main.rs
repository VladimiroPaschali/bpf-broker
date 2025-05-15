use clap::Parser;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
    Mutex,
};
use std::thread;
use std::time::{Duration, Instant};
use rand::distributions::{Distribution, Uniform};

#[derive(Parser, Debug)]
#[command(name = "UDP Benchmark Client", about = "Simulates many publishers sending to a broker")]
struct Args {
    #[arg(long)]
    topic: String,
    #[arg(long)]
    subs: usize,
    #[arg(long, default_value_t = 1450)]
    size: usize,
    #[arg(long, default_value_t = 1)]
    pubs: usize,
    #[arg(long, default_value = "10.10.1.1")]
    broker_ip: String,
    #[arg(long, default_value_t = 49152)]
    broker_port: u16,
    #[arg(long, default_value_t = 30)]
    duration: u64,
}

/// Send a UDP "REGISTER <topic>" message to the broker and wait for optional response
fn register_topic(topic: &str, broker: SocketAddr) {
    let sock = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind register socket");
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    let msg = format!("REGISTER {}", topic);
    println!("[>] Sending: {}", msg);
    if let Err(e) = sock.send_to(msg.as_bytes(), broker) {
        eprintln!("[!] Failed to send: {}", e);
    }

    let mut buf = [0u8; 1024];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => {
            let reply = String::from_utf8_lossy(&buf[..n]);
            println!("[✓] Broker responded: {}", reply.trim());
        }
        Err(e) => {
            println!("[!] No response from broker (timeout): {}", e);
        }
    }
}

/// Start a subscriber that sends SUBSCRIBE <topic> and listens (optional for full flow)
fn spawn_subscriber_with_latency(topic: String, id: usize, broker: SocketAddr, duration: Duration, latency_vec: Arc<Mutex<Vec<u128>>>) {
    thread::spawn(move || {
        let port = (15000 + id) as u16;
        let sock = UdpSocket::bind(("0.0.0.0", port)).expect("Failed to bind subscriber socket");
        let sub_msg = format!("SUBSCRIBE {}", topic);
        if let Err(e) = sock.send_to(sub_msg.as_bytes(), broker) {
            eprintln!("[!] Failed to send: {}", e);
        }
        sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let start = Instant::now();
        let mut buf = vec![0u8; 2048];
        while start.elapsed() < duration {
            match sock.recv_from(&mut buf) {
                Ok((n, _src)) => {
                    // Assume message format: "PUBLISH <topic> <timestamp> <payload>"
                    let msg = &buf[..n];
                    let msg_str = String::from_utf8_lossy(msg);
                    let mut parts = msg_str.splitn(4, ' ');
                    let _publish = parts.next();
                    let _topic = parts.next();
                    let ts_str = parts.next();
                    if let Some(ts_str) = ts_str {
                        if let Ok(sent_ns) = ts_str.parse::<u128>() {
                            let now_ns = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_nanos();
                            let latency = now_ns.saturating_sub(sent_ns);
                            if let Ok(mut latencies) = latency_vec.lock() {
                                latencies.push(latency);
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    // Timeout, just continue
                }
                Err(e) => {
                    eprintln!("[!] Subscriber {} recv error: {}", id, e);
                }
            }
        }
    });
}

fn spawn_multiport_publisher_thread(
    duration: Duration,
    topic: String,
    broker_ip: String,
    dest_ports: Vec<u16>,
    global_counter: Arc<AtomicUsize>,
    msg_size: usize,
) {
    thread::spawn(move || {
        let port_range = Uniform::from(30000..40000);
        let mut rng = rand::thread_rng();
        let sock = loop {
            let random_port: u16 = port_range.sample(&mut rng);
            match UdpSocket::bind(("0.0.0.0", random_port)) {
                Ok(s) => break s,
                Err(_) => continue,
            }
        };
        let prefix = format!("PUBLISH {} ", topic);
        let prefix_len = prefix.len();
        // Reserve 20 bytes for timestamp (u128 as string + space)
        let ts_len = 20;
        let payload_size = msg_size.saturating_sub(prefix_len + ts_len);
        let payload_chars = Uniform::new(33, 127);
        let port_selector = Uniform::from(0..dest_ports.len());
        let start = Instant::now();
        while start.elapsed() < duration {
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let random_payload: String = (0..payload_size)
                .map(|_| char::from_u32(payload_chars.sample(&mut rng)).unwrap())
                .collect();
            let msg = format!("{}{} {}", prefix, now_ns, random_payload);
            // Randomly choose a destination port
            let port = dest_ports[port_selector.sample(&mut rng)];
            let broker = format!("{}:{}", broker_ip, port)
                .parse::<SocketAddr>()
                .unwrap();
            if let Err(e) = sock.send_to(msg.as_bytes(), broker) {
                eprintln!("[!] Failed to send: {}", e);
            }
            global_counter.fetch_add(1, Ordering::Relaxed);
        }
    });
}

fn main() {
    let args = Args::parse();

    let broker_addr: SocketAddr = format!("{}:{}", args.broker_ip, args.broker_port)
        .parse()
        .expect("Invalid broker address");

    println!(
        "[*] Starting {} publishers and {} subscribers targeting {} for {}s, msg_size: {}B",
        args.pubs, args.subs, broker_addr, args.duration, args.size
    );

    let global_counter = Arc::new(AtomicUsize::new(0));
    let duration = Duration::from_secs(args.duration);

    // Step 1: Register the topic once
    register_topic(&args.topic, broker_addr);

    // Step 2: Start subscriber threads (with latency measurement)
    let latency_vec = Arc::new(Mutex::new(Vec::new()));
    for id in 0..args.subs {
        let latency_vec = latency_vec.clone();
        spawn_subscriber_with_latency(args.topic.clone(), id, broker_addr, duration, latency_vec);
    }

    thread::sleep(Duration::from_millis(500)); // Give subscribers a moment to connect

    // Step 3: Launch throughput reporter
    {
        let stats_counter = global_counter.clone();
        let duration_secs = args.duration;
        thread::spawn(move || {
            let mut last = 0;
            let mut second = 0;

            println!("\n[ ID] Interval        Transfer     Bandwidth");

            while second < duration_secs {
                thread::sleep(Duration::from_secs(1));
                second += 1;

                let total = stats_counter.load(Ordering::Relaxed);
                let delta = total - last;
                last = total;

                let bits = (delta * args.size * 8) as f64;
                let mbits = bits / 1_000_000.0;

                println!(
                    "[{:<3}] {:>2}.0-{:<3}.0 sec   {:>8} msgs   {:>6.2} Mbits/sec",
                    5,
                    second - 1,
                    second,
                    delta,
                    mbits
                );
            }
        });
    }

    let dest_ports: Vec<u16> = (49152..49168).collect();

    for _ in 0..args.pubs {
        spawn_multiport_publisher_thread(
            duration,
            args.topic.clone(),
            args.broker_ip.clone(),
            dest_ports.clone(), // clone since each thread owns it
            global_counter.clone(),
            args.size,
        );
    }

    thread::sleep(duration + Duration::from_secs(2));

    let final_count = global_counter.load(Ordering::Relaxed);
    println!("\n=== Final Results ===");
    println!("Total Sent Messages : {}", final_count);
    println!(
        "Effective Throughput: {:.2} msgs/sec",
        final_count as f64 / args.duration as f64
    );

    // Print latency statistics
    if let Ok(latencies) = latency_vec.lock() {
        if !latencies.is_empty() {
            let min = latencies.iter().min().unwrap();
            let max = latencies.iter().max().unwrap();
            let avg = latencies.iter().sum::<u128>() as f64 / latencies.len() as f64;
            let mut sorted_latencies = latencies.clone();
            sorted_latencies.sort_unstable();
            let p99 = sorted_latencies[sorted_latencies.len() * 99 / 100];
            let p50 = sorted_latencies[sorted_latencies.len() * 50 / 100];
            let p90 = sorted_latencies[sorted_latencies.len() * 90 / 100];
            println!("Latency (us): received={}, min={}, max={}, avg={:.0}, p50={:.0}, p90={:.0}, p99={:.0}",
                latencies.len(),
                min / 1000,
                max / 1000,
                avg / 1000.0,
                p50 / 1000,
                p90 / 1000,
                p99 / 1000
            );
        } else {
            println!("No messages received by subscribers.");
        }
    }
}
