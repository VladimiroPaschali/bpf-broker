use dashmap::DashMap;
use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::str;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;

type Topic = String;
type SubscriberSet = HashSet<SocketAddr>;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:11211")?;
    socket.set_nonblocking(true)?;
    println!("[broker] Listening on 0.0.0.0:11211");

    let topics: Arc<DashMap<Topic, SubscriberSet>> = Arc::new(DashMap::new());
    let publish_counter = Arc::new(AtomicUsize::new(0));
    let clone_counter = Arc::new(AtomicUsize::new(0));

    let socket = Arc::new(socket);

    let socket_clone = Arc::clone(&socket);
    let topics_clone = Arc::clone(&topics);
    let pub_count = Arc::clone(&publish_counter);
    let clone_count = Arc::clone(&clone_counter);

    thread::spawn(move || loop {
        let mut buf = [0u8; 4096];

        match socket_clone.recv_from(&mut buf) {
            Ok((n, addr)) => {
                let msg = String::from_utf8_lossy(&buf[..n]).to_string();
                handle_message(
                    &msg,
                    addr,
                    &socket_clone,
                    &topics_clone,
                    &pub_count,
                    &clone_count,
                );
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => {
                eprintln!("[!] recv error: {}", e);
            }
        }
    });

    // Show live stats every 5 seconds
    loop {
        thread::sleep(std::time::Duration::from_secs(5));
        let pub_total = publish_counter.load(Ordering::Relaxed);
        let clone_total = clone_counter.load(Ordering::Relaxed);
        println!(
            "[stats] Received PUBLISH: {}, Cloned to subscribers: {}",
            pub_total, clone_total
        );
    }
}

fn handle_message(
    msg: &str,
    sender: SocketAddr,
    sock: &UdpSocket,
    topics: &DashMap<Topic, SubscriberSet>,
    publish_counter: &AtomicUsize,
    clone_counter: &AtomicUsize,
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
                publish_counter.fetch_add(1, Ordering::Relaxed);

                if let Some(subs) = topics.get(topic) {
                    for sub in subs.iter() {
                        let _ = sock.send_to(payload.as_bytes(), *sub);
                        clone_counter.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    println!("[publish] No topic '{}' registered", topic);
                }
            }
        }
        _ => {
            println!("[!] Unknown command from {}: {}", sender, msg);
        }
    }
}
