use clap::Parser;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
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
    size: usize,
    #[arg(long)]
    subs: usize,
    #[arg(long, default_value_t = 256)]
    pubs: usize,
    #[arg(long, default_value = "10.10.1.1")]
    broker_ip: String,
    #[arg(long, default_value_t = 11211)]
    broker_port: u16,
    #[arg(long, default_value_t = 150000)]
    rate: u64,
    #[arg(long, default_value_t = 30)]
    duration: u64,
}

/// Send a UDP "REGISTER <topic>" message to the broker and wait for optional response
fn register_topic(topic: &str, broker: SocketAddr) {
    let sock = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind register socket");
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    let msg = format!("REGISTER {}", topic);
    println!("[>] Sending: {}", msg);
    let _ = sock.send_to(msg.as_bytes(), broker);

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
fn spawn_subscriber(topic: String, id: usize, broker: SocketAddr) {
    thread::spawn(move || {
        let port = (15000 + id) as u16;
        let sock = UdpSocket::bind(("0.0.0.0", port)).expect("Failed to bind subscriber socket");
        let sub_msg = format!("SUBSCRIBE {}", topic);
        let _ = sock.send_to(sub_msg.as_bytes(), broker);
    });
}

/// Each publisher thread sends messages to the broker at a constant rate
fn spawn_publisher_thread(
    rate: u64,
    duration: Duration,
    topic: String,
    broker: SocketAddr,
    global_counter: Arc<AtomicUsize>,
    msg_size: usize,
) {
    thread::spawn(move || {
        let port_range = Uniform::from(30000..40000);
        let mut rng = rand::thread_rng();
        let random_port: u16 = port_range.sample(&mut rng);

        let sock = UdpSocket::bind(("0.0.0.0", random_port))
            .unwrap_or_else(|e| panic!("Failed to bind UDP socket on port {}: {}", random_port, e));

        let start = Instant::now();

        let prefix = format!("PUBLISH {} ", topic);
        let prefix_len = prefix.len();
        
        // Adjust payload size to account for prefix
        let payload_size = if msg_size > prefix_len {
            msg_size - prefix_len
        } else {
            println!("[Warning] Requested message size {} is too small for prefix length {}. Using minimum size.", msg_size, prefix_len);
            1  // Minimum 1 character payload
        };

        let mut rng = rand::thread_rng();
        let char_range = Uniform::new(33, 127);
        
        while start.elapsed() < duration {
            let half_start = Instant::now();
            let mut sent_this_half = 0;
            let random_payload: String = (0..payload_size)
                .map(|_| char::from_u32(char_range.sample(&mut rng)).unwrap())
                .collect();

            while sent_this_half < rate / 2 {
                let msg = format!("{}{}", prefix, random_payload);
                let _ = sock.send_to(msg.as_bytes(), broker);
                global_counter.fetch_add(1, Ordering::Relaxed);
                sent_this_half += 1;
            }

            // Sleep for the remainder of the half-second window if finished early
            let elapsed = half_start.elapsed();
            if elapsed < Duration::from_millis(500) {
                thread::sleep(Duration::from_millis(500) - elapsed);
            }
        }
    });
}

fn main() {
    let args = Args::parse();

    let broker_addr: SocketAddr = format!("{}:{}", args.broker_ip, args.broker_port)
        .parse()
        .expect("Invalid broker address");

    println!(
        "[*] Starting {} publishers and {} subscribers targeting {} for {}s at {} msg/sec (total), msg_size: {}B",
        args.pubs, args.subs, broker_addr, args.duration, args.rate, args.size
    );

    let global_counter = Arc::new(AtomicUsize::new(0));
    let per_publisher_rate = args.rate / args.pubs as u64;
    let duration = Duration::from_secs(args.duration);

    // Step 1: Register the topic once
    register_topic(&args.topic, broker_addr);

    // Step 2: Start subscriber threads (optional, for full flow testing)
    for id in 0..args.subs {
        spawn_subscriber(args.topic.clone(), id, broker_addr);
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

                // Assume 64-byte messages
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

    // Step 4: Launch publishers
    for _ in 0..args.pubs {
        spawn_publisher_thread(
            per_publisher_rate,
            duration,
            args.topic.clone(),
            broker_addr,
            global_counter.clone(),
            args.size,
        );
    }

    thread::sleep(duration + Duration::from_secs(2)); // Let threads finish

    let final_count = global_counter.load(Ordering::Relaxed);
    println!("\n=== Final Results ===");
    println!("Total Sent Messages : {}", final_count);
    println!(
        "Effective Throughput: {:.2} msgs/sec",
        final_count as f64 / args.duration as f64
    );
}
