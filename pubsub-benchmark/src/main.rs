use clap::Parser;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "UDP Benchmark Client", about = "Simulates many publishers sending to a broker")]
struct Args {
    #[arg(long)]
    topic: String,
    #[arg(long, default_value = "10.10.1.1")]
    broker_ip: String,
    #[arg(long, default_value_t = 11211)]
    broker_port: u16,
    #[arg(long, default_value_t = 340)]
    clients: usize,
    #[arg(long, default_value_t = 10)]
    duration: u64, // seconds
    #[arg(long, default_value_t = 10_000)]
    rate: u64, // total messages per second
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
        let port = 20000 + id as u16;
        let sock = UdpSocket::bind(("0.0.0.0", port)).expect("Failed to bind subscriber socket");
        let sub_msg = format!("SUBSCRIBE {}", topic);
        let _ = sock.send_to(sub_msg.as_bytes(), broker);

        let mut buf = [0u8; 4096];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((_len, _)) => {
                    // Optionally log received message
                }
                Err(_) => break,
            }
        }
    });
}

/// Each publisher thread sends messages to the broker at a constant rate
fn spawn_client_thread(
    id: usize,
    rate: u64,
    duration: Duration,
    topic: String,
    broker: SocketAddr,
    global_counter: Arc<AtomicUsize>,
) {
    thread::spawn(move || {
        let sock = UdpSocket::bind(("0.0.0.0", 30000 + id as u16))
            .expect("Failed to bind UDP socket");

        let interval = Duration::from_nanos(1_000_000_000 / rate);
        let start = Instant::now();
        let mut local_count = 0;

        while start.elapsed() < duration {
            let msg = format!("PUBLISH {} client{}-{}", topic, id, local_count);
            let _ = sock.send_to(msg.as_bytes(), broker);
            local_count += 1;
            global_counter.fetch_add(1, Ordering::Relaxed);
            thread::sleep(interval);
        }

        println!("[client {:03}] sent {} messages", id, local_count);
    });
}

fn main() {
    let args = Args::parse();

    let broker_addr: SocketAddr = format!("{}:{}", args.broker_ip, args.broker_port)
        .parse()
        .expect("Invalid broker address");

    println!(
        "[*] Starting {} clients targeting {} for {}s at {} msg/sec (total)",
        args.clients, broker_addr, args.duration, args.rate
    );

    let global_counter = Arc::new(AtomicUsize::new(0));
    let per_client_rate = args.rate / args.clients as u64;
    let duration = Duration::from_secs(args.duration);

    // Step 1: Register the topic once
    register_topic(&args.topic, broker_addr);

    // Step 2: Start subscriber threads (optional, for full flow testing)
    for id in 0..args.clients {
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
                let bits = (delta * 64 * 8) as f64;
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

    // Step 4: Launch client publishers
    for id in 0..args.clients {
        spawn_client_thread(
            id,
            per_client_rate,
            duration,
            args.topic.clone(),
            broker_addr,
            global_counter.clone(),
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
