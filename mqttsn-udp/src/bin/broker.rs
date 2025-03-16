use std::collections::{HashMap, HashSet};
use std::net::{UdpSocket, SocketAddr};
use std::str;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:5000")?;
    println!("Broker listening on udp://0.0.0.0:5000");

    let mut next_topic_id: u16 = 1;
    let mut topic_name_to_id = HashMap::new();
    let mut topic_id_to_subs: HashMap<u16, HashSet<SocketAddr>> = HashMap::new();

    let mut buf = [0u8; 1024];
    loop {
        let (len, src) = socket.recv_from(&mut buf)?;
        let msg = str::from_utf8(&buf[..len]).unwrap_or("");
        let parts: Vec<&str> = msg.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0].to_uppercase().as_str() {
            "REGISTER" if parts.len() >= 2 => {
                let topic = parts[1];
                let tid = *topic_name_to_id.entry(topic.to_string()).or_insert_with(|| {
                    let id = next_topic_id;
                    next_topic_id += 1;
                    topic_id_to_subs.insert(id, HashSet::new());
                    id
                });
                let response = format!("REGACK {} {}", topic, tid);
                socket.send_to(response.as_bytes(), src)?;
            }
            "SUBSCRIBE" if parts.len() >= 2 => {
                let topic = parts[1];
                let tid = *topic_name_to_id.entry(topic.to_string()).or_insert_with(|| {
                    let id = next_topic_id;
                    next_topic_id += 1;
                    topic_id_to_subs.insert(id, HashSet::new());
                    id
                });
                topic_id_to_subs.get_mut(&tid).unwrap().insert(src);
                let response = format!("SUBACK {} {}", topic, tid);
                socket.send_to(response.as_bytes(), src)?;
            }
            "PUBLISH" if parts.len() >= 3 => {
                if let Ok(tid) = parts[1].parse::<u16>() {
                    let payload = parts[2..].join(" ");
                    let msg_out = format!("PUBLISH {} {}", tid, payload);
                    if let Some(subs) = topic_id_to_subs.get(&tid) {
                        for sub in subs {
                            let _ = socket.send_to(msg_out.as_bytes(), sub);
                        }
                    }
                    let ack = format!("PUBACK {}", tid);
                    socket.send_to(ack.as_bytes(), src)?;
                }
            }
            _ => {
                let err = "ERROR Unknown or malformed command";
                socket.send_to(err.as_bytes(), src)?;
            }
        }
    }
}
