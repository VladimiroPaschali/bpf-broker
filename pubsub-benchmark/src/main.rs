use clap::Parser;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
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
    /// Skip latency parsing: subscribers just drain the socket (max throughput mode)
    #[arg(long, default_value_t = false)]
    sink: bool,
    /// Max packets per second per publisher thread (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    rate_pps: u64,
}

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

/// Parse timestamp from raw message bytes: "PUBLISH <topic> <ts> <payload>"
/// Returns the nanosecond timestamp without any heap allocation.
fn parse_timestamp_ns(msg: &[u8]) -> Option<u128> {
    let mut spaces = 0u8;
    let mut ts_start = 0;
    for (i, &b) in msg.iter().enumerate() {
        if b == b' ' {
            spaces += 1;
            if spaces == 2 {
                ts_start = i + 1;
            } else if spaces == 3 {
                return parse_decimal_u128(&msg[ts_start..i]);
            }
        }
    }
    // timestamp goes to end of message (no payload after it)
    if spaces == 2 && ts_start < msg.len() {
        return parse_decimal_u128(&msg[ts_start..]);
    }
    None
}

fn parse_decimal_u128(bytes: &[u8]) -> Option<u128> {
    if bytes.is_empty() {
        return None;
    }
    let mut val: u128 = 0;
    for &b in bytes {
        if b < b'0' || b > b'9' {
            return None;
        }
        val = val.wrapping_mul(10).wrapping_add((b - b'0') as u128);
    }
    Some(val)
}

/// Write a u128 decimal value into a fixed-width byte slice (zero-padded on left).
/// Must NOT use space padding: the subscriber splits on spaces to find the timestamp field.
fn write_u128_fixed(buf: &mut [u8], val: u128) {
    let width = buf.len();
    let mut tmp = [b'0'; 39];
    let mut v = val;
    let mut pos = 39;
    if v == 0 {
        pos -= 1;
        tmp[pos] = b'0';
    } else {
        while v > 0 {
            pos -= 1;
            tmp[pos] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    let digits = &tmp[pos..];
    let dlen = digits.len();
    if dlen >= width {
        buf.copy_from_slice(&digits[dlen - width..]);
    } else {
        let pad = width - dlen;
        buf[..pad].fill(b'0');
        buf[pad..].copy_from_slice(digits);
    }
}

struct SubResult {
    raw_received: usize,
    latencies: Vec<u128>,
}

fn spawn_subscriber(
    topic: String,
    id: usize,
    broker: SocketAddr,
    running: Arc<AtomicBool>,
    sink: bool,
    recv_counter: Arc<AtomicUsize>,
) -> thread::JoinHandle<SubResult> {
    const BATCH: usize = 64;
    const PKT_BUF: usize = 2048;

    thread::spawn(move || {
        let port = (15000 + id) as u16;
        let sock = UdpSocket::bind(("0.0.0.0", port)).expect("Failed to bind subscriber socket");
        let sub_msg = format!("SUBSCRIBE {}", topic);
        if let Err(e) = sock.send_to(sub_msg.as_bytes(), broker) {
            eprintln!("[!] Failed to send SUBSCRIBE: {}", e);
        }

        // SO_RCVBUFFORCE bypasses rmem_max cap (requires CAP_NET_ADMIN / root).
        // Falls back to SO_RCVBUF (capped by net.core.rmem_max) if not root.
        let rcvbuf: libc::c_int = 8 * 1024 * 1024;
        let fd = sock.as_raw_fd();
        unsafe {
            let ok = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                &rcvbuf as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ok != 0 {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &rcvbuf as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
        sock.set_nonblocking(true).expect("Failed to set subscriber nonblocking mode");

        let mut raw_received: usize = 0;
        let mut parse_errors: usize = 0;
        let mut latencies: Vec<u128> = Vec::new();

        // Pre-allocate BATCH receive buffers and mmsghdr structures
        let mut bufs: Vec<Vec<u8>> = vec![vec![0u8; PKT_BUF]; BATCH];
        let mut iovecs: Vec<libc::iovec> = bufs.iter_mut()
            .map(|b| libc::iovec { iov_base: b.as_mut_ptr() as *mut _, iov_len: PKT_BUF })
            .collect();
        let mut mmsghdrs: Vec<libc::mmsghdr> = vec![unsafe { std::mem::zeroed() }; BATCH];
        for i in 0..BATCH {
            mmsghdrs[i].msg_hdr.msg_iov    = &mut iovecs[i];
            mmsghdrs[i].msg_hdr.msg_iovlen = 1;
        }

        while running.load(Ordering::Relaxed) {
            let n = unsafe {
                libc::recvmmsg(
                    fd,
                    mmsghdrs.as_mut_ptr(),
                    BATCH as libc::c_uint,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                )
            };
            if n <= 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or_default();
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                if errno == libc::EINTR {
                    continue;
                }
                continue;
            }
            let n = n as usize;
            raw_received += n;
            recv_counter.fetch_add(n, Ordering::Relaxed);

            if sink {
                continue;
            }

            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();

            for i in 0..n {
                let pkt_len = mmsghdrs[i].msg_len as usize;
                if let Some(sent_ns) = parse_timestamp_ns(&bufs[i][..pkt_len]) {
                    latencies.push(now_ns.saturating_sub(sent_ns));
                } else {
                    parse_errors += 1;
                    if parse_errors == 1 {
                        eprintln!(
                            "[!] sub#{}: cannot parse timestamp from: {:?}",
                            id,
                            String::from_utf8_lossy(&bufs[i][..pkt_len.min(80)])
                        );
                    }
                }
            }
        }
        SubResult { raw_received, latencies }
    })
}

/// Convert a `SocketAddr` (IPv4) to a raw `sockaddr_in` for use with sendmmsg.
fn to_sockaddr_in(addr: SocketAddr) -> libc::sockaddr_in {
    match addr {
        SocketAddr::V4(v4) => libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: v4.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(*v4.ip()).to_be(),
            },
            sin_zero: [0; 8],
        },
        SocketAddr::V6(_) => panic!("IPv6 not supported"),
    }
}

fn spawn_publisher_thread(
    duration: Duration,
    topic: String,
    broker_ip: String,
    dest_ports: Vec<u16>,
    global_counter: Arc<AtomicUsize>,
    msg_size: usize,
    rate_pps: u64,
) {
    const BATCH: usize = 64;

    thread::spawn(move || {
        let port_range = Uniform::from(30000..40000u16);
        let mut rng = rand::thread_rng();

        let sock = loop {
            let p: u16 = port_range.sample(&mut rng);
            match UdpSocket::bind(("0.0.0.0", p)) {
                Ok(s) => break s,
                Err(_) => continue,
            }
        };
        let fd = sock.as_raw_fd();

        // Pre-parse all destination SocketAddrs
        let brokers: Vec<libc::sockaddr_in> = dest_ports
            .iter()
            .map(|p| {
                let addr: SocketAddr = format!("{}:{}", broker_ip, p).parse().unwrap();
                to_sockaddr_in(addr)
            })
            .collect();

        // Message layout: "PUBLISH <topic> <ts_20bytes> <payload>"
        let prefix = format!("PUBLISH {} ", topic);
        const TS_LEN: usize = 20;
        let payload_size = msg_size.saturating_sub(prefix.len() + TS_LEN + 1);

        let payload_chars = Uniform::new(33u8, 127u8);
        let payload: Vec<u8> = (0..payload_size).map(|_| payload_chars.sample(&mut rng)).collect();

        let mut msg_buf: Vec<u8> = Vec::with_capacity(prefix.len() + TS_LEN + 1 + payload_size);
        msg_buf.extend_from_slice(prefix.as_bytes());
        let ts_start = msg_buf.len();
        msg_buf.resize(ts_start + TS_LEN, b'0');
        msg_buf.push(b' ');
        msg_buf.extend_from_slice(&payload);

        // Pre-allocate sendmmsg structures. All BATCH entries share the same msg_buf
        // (same timestamp per batch), only the destination address varies.
        let mut addrs: Vec<libc::sockaddr_in> = vec![unsafe { std::mem::zeroed() }; BATCH];
        let mut iovecs: Vec<libc::iovec> = vec![libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; BATCH];
        let mut mmsghdrs: Vec<libc::mmsghdr> = vec![unsafe { std::mem::zeroed() }; BATCH];

        let broker_selector = Uniform::from(0..brokers.len());
        let start = Instant::now();
        let mut total_sent: u64 = 0;

        while start.elapsed() < duration {
            // One timestamp per batch — BATCH packets share it
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            write_u128_fixed(&mut msg_buf[ts_start..ts_start + TS_LEN], now_ns);

            // Fill batch: each entry gets a (possibly different) destination
            for i in 0..BATCH {
                addrs[i] = brokers[broker_selector.sample(&mut rng)];
                iovecs[i].iov_base = msg_buf.as_ptr() as *mut libc::c_void;
                iovecs[i].iov_len = msg_buf.len();

                let hdr = &mut mmsghdrs[i].msg_hdr;
                hdr.msg_name = &mut addrs[i] as *mut _ as *mut libc::c_void;
                hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
                hdr.msg_iov = &mut iovecs[i];
                hdr.msg_iovlen = 1;
                hdr.msg_control = std::ptr::null_mut();
                hdr.msg_controllen = 0;
                hdr.msg_flags = 0;
                mmsghdrs[i].msg_len = 0;
            }

            // One syscall sends all BATCH packets
            let sent = unsafe {
                libc::sendmmsg(fd, mmsghdrs.as_mut_ptr(), BATCH as libc::c_uint, 0)
            };
            if sent > 0 {
                let n = sent as u64;
                global_counter.fetch_add(n as usize, Ordering::Relaxed);
                total_sent += n;

                // Pace to --rate-pps: sleep if we're ahead of schedule
                if rate_pps > 0 {
                    let target = Duration::from_secs_f64(total_sent as f64 / rate_pps as f64);
                    let elapsed = start.elapsed();
                    if target > elapsed {
                        thread::sleep(target - elapsed);
                    }
                }
            }
        }
    });
}

fn main() {
    let args = Args::parse();

    let broker_addr: SocketAddr = format!("{}:{}", args.broker_ip, args.broker_port)
        .parse()
        .expect("Invalid broker address");

    let rate_str = if args.rate_pps > 0 {
        format!(" rate={}pps ({:.0}Mbit/s)", args.rate_pps,
            args.rate_pps as f64 * args.size as f64 * 8.0 / 1_000_000.0)
    } else {
        " rate=unlimited".to_string()
    };
    println!(
        "[*] Starting {} publishers and {} subscribers targeting {} for {}s, msg_size: {}B{}{}",
        args.pubs, args.subs, broker_addr, args.duration, args.size,
        rate_str,
        if args.sink { " [sink]" } else { "" },
    );

    let global_counter = Arc::new(AtomicUsize::new(0));
    let recv_counter  = Arc::new(AtomicUsize::new(0));
    let running = Arc::new(AtomicBool::new(true));
    let duration = Duration::from_secs(args.duration);

    register_topic(&args.topic, broker_addr);

    // Subscriber threads — each owns its latency Vec, no shared mutex
    let sub_handles: Vec<_> = (0..args.subs)
        .map(|id| spawn_subscriber(
            args.topic.clone(), id, broker_addr, running.clone(), args.sink,
            recv_counter.clone(),
        ))
        .collect();

    thread::sleep(Duration::from_millis(500));

    // Throughput reporter — TX and RX side by side
    {
        let tx_counter = global_counter.clone();
        let rx_counter = recv_counter.clone();
        let duration_secs = args.duration;
        let msg_size = args.size;
        thread::spawn(move || {
            let mut last_tx = 0usize;
            let mut last_rx = 0usize;
            println!(
                "\n{:<12}  {:>10}  {:>10}  {:>10}  {:>10}",
                "Interval", "TX msgs", "TX Mbit/s", "RX msgs", "RX Mbit/s"
            );
            for second in 1..=duration_secs {
                thread::sleep(Duration::from_secs(1));

                let tx = tx_counter.load(Ordering::Relaxed);
                let rx = rx_counter.load(Ordering::Relaxed);
                let dtx = tx - last_tx;
                let drx = rx - last_rx;
                last_tx = tx;
                last_rx = rx;

                let tx_mbits = (dtx * msg_size * 8) as f64 / 1_000_000.0;
                let rx_mbits = (drx * msg_size * 8) as f64 / 1_000_000.0;

                println!(
                    "{:>2}.0-{:<2}.0 sec    {:>10}  {:>10.2}  {:>10}  {:>10.2}",
                    second - 1, second,
                    dtx, tx_mbits,
                    drx, rx_mbits,
                );
            }
        });
    }

    let dest_ports: Vec<u16> = (49152..49168).collect();

    for _ in 0..args.pubs {
        spawn_publisher_thread(
            duration,
            args.topic.clone(),
            args.broker_ip.clone(),
            dest_ports.clone(),
            global_counter.clone(),
            args.size,
            args.rate_pps,
        );
    }

    thread::sleep(duration + Duration::from_secs(2));
    running.store(false, Ordering::Relaxed);

    let final_tx = global_counter.load(Ordering::Relaxed);

    // Collect per-thread results — no mutex, just join
    let results: Vec<SubResult> = sub_handles
        .into_iter()
        .filter_map(|h| h.join().ok())
        .collect();

    let total_raw: usize = results.iter().map(|r| r.raw_received).sum();
    let mut all_latencies: Vec<u128> = results.into_iter().flat_map(|r| r.latencies).collect();

    println!("\n=== Final Results ===");
    println!(
        "TX: {:>10} msgs   {:.2} msgs/sec   {:.2} Mbit/s",
        final_tx,
        final_tx as f64 / args.duration as f64,
        (final_tx * args.size * 8) as f64 / 1_000_000.0 / args.duration as f64,
    );
    println!(
        "RX: {:>10} msgs   {:.2} msgs/sec   {:.2} Mbit/s",
        total_raw,
        total_raw as f64 / args.duration as f64,
        (total_raw * args.size * 8) as f64 / 1_000_000.0 / args.duration as f64,
    );

    if !all_latencies.is_empty() {
        let min = *all_latencies.iter().min().unwrap();
        let max = *all_latencies.iter().max().unwrap();
        let avg = all_latencies.iter().sum::<u128>() as f64 / all_latencies.len() as f64;
        all_latencies.sort_unstable();
        let n = all_latencies.len();
        let p50 = all_latencies[n * 50 / 100];
        let p90 = all_latencies[n * 90 / 100];
        let p99 = all_latencies[n * 99 / 100];
        println!(
            "Latency (us): received={}, min={}, max={}, avg={:.0}, p50={:.0}, p90={:.0}, p99={:.0}",
            n,
            min / 1000,
            max / 1000,
            avg / 1000.0,
            p50 / 1000,
            p90 / 1000,
            p99 / 1000
        );
    } else if total_raw > 0 {
        println!("Packets arrived ({}) but timestamp parse failed — check message format.", total_raw);
    } else {
        println!("No packets received by subscribers.");
    }
}
