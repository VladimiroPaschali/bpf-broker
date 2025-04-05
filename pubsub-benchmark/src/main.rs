use clap::Parser;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    topic: String,
    #[arg(long, default_value = "10.10.1.1")]
    broker_ip: String,
    #[arg(long, default_value_t = 11211)]
    broker_port: u16,
    #[arg(long, default_value_t = 10)]
    subs: usize,
    #[arg(long, default_value_t = 1000)]
    msgs: usize,
}

fn spawn_subscriber(
    topic: String,
    port: u16,
    broker: SocketAddr,
    counter: Arc<AtomicUsize>,
) {
    thread::spawn(move || {
        let sock = UdpSocket::bind(("0.0.0.0", port)).expect("Failed to bind subscriber socket");

        let sub_msg = format!("SUBSCRIBE {}", topic);
        sock.send_to(sub_msg.as_bytes(), broker).unwrap();

        let mut buf = [0u8; 4096];
        loop {
            match sock.recv_from(&mut buf) {
                Ok((_len, _addr)) => {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    eprintln!("[!] recv error: {}", e);
                    break;
                }
            }
        }
    });
}


fn register_topic(topic: &str, broker_ip: &str, broker_port: u16) -> std::io::Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?; // Bind to any available port
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;

    let msg = format!("REGISTER {}", topic);
    let broker = format!("{}:{}", broker_ip, broker_port);

    println!("[>] Sending: {}", msg);
    sock.send_to(msg.as_bytes(), &broker)?;

    let mut buf = [0u8; 1024];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => {
            let reply = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            println!("[✓] Broker responded: {}", reply);
        }
        Err(e) => {
            println!("[!] No response from broker (timeout): {}", e);
        }
    }

    Ok(())
}


fn main() {
    let args = Args::parse();

    let broker = format!("{}:{}", args.broker_ip, args.broker_port);
    let broker_addr: SocketAddr = broker.parse().expect("Invalid broker address");

    // Step 1: Register the topic
    if let Err(e) = register_topic(&args.topic, &args.broker_ip, args.broker_port) {
        eprintln!("Failed to register topic: {}", e);
        std::process::exit(1);
    }

    // Step 2: Start subscribers
    let counter = Arc::new(AtomicUsize::new(0));
    let base_port = 20000;

    for i in 0..args.subs {
        let port = base_port + i as u16;
        let topic = args.topic.clone();
        let counter = counter.clone();
        spawn_subscriber(topic, port, broker_addr, counter);
    }

    println!("[+] Spawned {} subscribers", args.subs);
    thread::sleep(Duration::from_millis(1000)); // wait for subscriptions

    // Step 3: Send PUBLISH messages
    let sock = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind publisher socket");

    println!("[>] Sending {} messages to topic '{}'", args.msgs, args.topic);
    for i in 0..args.msgs {
        let msg = format!("PUBLISH {} msg-{}", args.topic, i);
        sock.send_to(msg.as_bytes(), broker_addr).unwrap();
    }

    // Step 4: Wait until all expected messages are received
    let expected = args.msgs * args.subs;
    let timeout = Duration::from_secs(20);
    let poll_interval = Duration::from_millis(50);
    let wait_start = Instant::now();

    loop {
        let current = counter.load(Ordering::Relaxed);
        if current >= expected {
            break;
        }
        if wait_start.elapsed() >= timeout {
            println!("[!] Timeout reached while waiting for messages");
            break;
        }
        thread::sleep(poll_interval);
    }

    let elapsed = wait_start.elapsed().as_secs_f64();
    let total_received = counter.load(Ordering::Relaxed);

    println!("\n=== Benchmark Results ===");
    println!("Subscribers         : {}", args.subs);
    println!("Messages Published  : {}", args.msgs);
    println!("Messages Received   : {}", total_received);
    println!("Elapsed Time        : {:.2} seconds", elapsed);
    println!("Effective Throughput: {:.2} msgs/sec", total_received as f64 / elapsed);
}
