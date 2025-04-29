use clap::Parser;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use rand::Rng;
use std::collections::HashMap;

const NUM_TOPICS: usize = 20;
const MSG_RATE_PER_TOPIC: u64 = 1500; // messages per second per topic
const MIN_SUBS: usize = 1;
const MAX_SUBS: usize = 100;

#[derive(Parser, Debug)]
#[command(name = "Mixed Workload Benchmark", about = "Simulates mixed workload with uniform subscriber distribution")]
struct Args {
    #[arg(long, default_value = "10.10.1.1")]
    broker_ip: String,
    #[arg(long, default_value_t = 11211)]
    broker_port: u16,
    #[arg(long, default_value_t = 30)]
    duration: u64, // seconds
    #[arg(long, default_value_t = 64)]
    msg_size: usize, // message size in bytes
}

struct TopicConfig {
    name: String,
    sub_count: usize,
}

fn generate_topic_configs() -> Vec<TopicConfig> {
    let mut rng = rand::thread_rng();
    
    (0..NUM_TOPICS)
        .map(|i| {
            let sub_count = rng.gen_range(MIN_SUBS..=MAX_SUBS);
            TopicConfig {
                name: format!("topic{}", i),
                sub_count,
            }
        })
        .collect()
}

fn register_topic_and_subscribers(
    topic: &str,
    num_subs: usize,
    broker_addr: SocketAddr,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();
    
    // Register topic
    let sock = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind register socket");
    let msg = format!("REGISTER {}", topic);
    let _ = sock.send_to(msg.as_bytes(), broker_addr);
    
    // Start subscribers
    for id in 0..num_subs {
        let topic = topic.to_string();
        let broker = broker_addr;
        handles.push(thread::spawn(move || {
            let port = (20000 + id) as u16;
            if let Ok(sock) = UdpSocket::bind(("0.0.0.0", port)) {
                let sub_msg = format!("SUBSCRIBE {}", topic);
                let _ = sock.send_to(sub_msg.as_bytes(), broker);
                
                let mut buf = [0u8; 4096];
                while let Ok(_) = sock.recv_from(&mut buf) {
                    // Just receive messages
                }
            }
        }));
    }
    
    handles
}

fn spawn_publisher(
    topic: String,
    broker_addr: SocketAddr,
    msg_size: usize,
    global_counter: Arc<AtomicUsize>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            let interval = Duration::from_nanos(1_000_000_000 / MSG_RATE_PER_TOPIC);
            let mut rng = rand::thread_rng();
            
            // Pre-generate random payload
            let prefix = format!("PUBLISH {} ", topic);
            let payload_size = msg_size.saturating_sub(prefix.len());
            let random_payload: String = (0..payload_size)
                .map(|_| (33 + (rng.gen::<u8>() % 94)) as char)
                .collect();
            let msg = format!("{}{}", prefix, random_payload);
            
            loop {
                let _ = sock.send_to(msg.as_bytes(), broker_addr);
                global_counter.fetch_add(1, Ordering::Relaxed);
                thread::sleep(interval);
            }
        }
    })
}

fn main() {
    let args = Args::parse();
    let broker_addr: SocketAddr = format!("{}:{}", args.broker_ip, args.broker_port)
        .parse()
        .expect("Invalid broker address");

    println!("Generating uniform workload configuration...");
    let topic_configs = generate_topic_configs();
    
    // Print distribution
    println!("\nSubscriber distribution:");
    let mut dist_map = HashMap::new();
    for config in &topic_configs {
        *dist_map.entry(config.sub_count).or_insert(0) += 1;
    }
    let mut dist: Vec<_> = dist_map.iter().collect();
    dist.sort_by_key(|&(k, _)| *k);
    for (subs, count) in dist {
        println!("{} subscribers: {} topics", subs, count);
    }

    println!("\nStarting benchmark:");
    println!("Topics: {}", NUM_TOPICS);
    println!("Message rate per topic: {} msg/sec", MSG_RATE_PER_TOPIC);
    println!("Message size: {} bytes", args.msg_size);
    println!("Duration: {} seconds", args.duration);
    
    let global_counter = Arc::new(AtomicUsize::new(0));
    let mut sub_handles = Vec::new();
    let mut pub_handles = Vec::new();
    
    // Start subscribers and publishers for each topic
    for config in topic_configs {
        println!("Setting up {} with {} subscribers", config.name, config.sub_count);
        sub_handles.extend(register_topic_and_subscribers(
            &config.name,
            config.sub_count,
            broker_addr,
        ));
        pub_handles.push(spawn_publisher(
            config.name,
            broker_addr,
            args.msg_size,
            global_counter.clone(),
        ));
    }
    
    // Stats reporting thread
    let stats_counter = global_counter.clone();
    let stats_handle = thread::spawn(move || {
        let start = Instant::now();
        let mut last_count = 0;
        
        while start.elapsed() < Duration::from_secs(args.duration) {
            thread::sleep(Duration::from_secs(1));
            let current_count = stats_counter.load(Ordering::Relaxed);
            let delta = current_count - last_count;
            
            println!(
                "[{:3}s] Rate: {:>8} msg/s, Total: {}",
                start.elapsed().as_secs(),
                delta,
                current_count,
            );
            
            last_count = current_count;
        }
    });
    
    // Wait for completion
    stats_handle.join().unwrap();
    println!("\nBenchmark complete!");
    println!("Total messages sent: {}", global_counter.load(Ordering::Relaxed));
}
