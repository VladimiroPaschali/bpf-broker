use std::net::{UdpSocket, SocketAddr};
use std::collections::{HashMap, HashSet};
use std::str;


#[cfg(feature = "broker")]
fn main() -> std::io::Result<()> {
    // 1) Bind to a well-known port for the broker
    let broker_addr = "0.0.0.0:5000";
    let socket = UdpSocket::bind(broker_addr)?;
    println!("Broker listening on {}", broker_addr);

    // 2) Data structures
    let mut next_topic_id: u16 = 1;
    let mut topic_name_to_id: HashMap<String, u16> = HashMap::new();
    let mut topic_id_to_subs: HashMap<u16, HashSet<SocketAddr>> = HashMap::new();

    // 3) Main loop: handle incoming messages
    let mut buf = [0u8; 1024];
    loop {
        let (received_len, src_addr) = socket.recv_from(&mut buf)?;
        let msg = str::from_utf8(&buf[..received_len]).unwrap_or("");
        // e.g. "REGISTER temperature"
        //      "SUBSCRIBE temperature"
        //      "PUBLISH 1 HelloWorld"

        let parts: Vec<&str> = msg.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let cmd = parts[0].to_uppercase();

        if cmd == "REGISTER" && parts.len() >= 2 {
            let topic_name = parts[1];
            // If topic_name unknown, assign a new ID
            let topic_id = *topic_name_to_id.entry(topic_name.to_string())
                                .or_insert_with(|| {
                                    let tid = next_topic_id;
                                    next_topic_id += 1;
                                    topic_id_to_subs.insert(tid, HashSet::new());
                                    tid
                                });
            // Send REGACK back
            let response = format!("REGACK {} {}", topic_name, topic_id);
            socket.send_to(response.as_bytes(), src_addr)?;
        }
        else if cmd == "SUBSCRIBE" && parts.len() >= 2 {
            let topic_name = parts[1];
            // Auto-register if not known
            let topic_id = *topic_name_to_id.entry(topic_name.to_string())
                                .or_insert_with(|| {
                                    let tid = next_topic_id;
                                    next_topic_id += 1;
                                    topic_id_to_subs.insert(tid, HashSet::new());
                                    tid
                                });
            // Add src_addr to the subscriber list
            if let Some(subs) = topic_id_to_subs.get_mut(&topic_id) {
                subs.insert(src_addr);
            }
            let response = format!("SUBACK {} {}", topic_name, topic_id);
            socket.send_to(response.as_bytes(), src_addr)?;
        }
        else if cmd == "PUBLISH" && parts.len() >= 3 {
            // "PUBLISH <topic_id> <message>"
            let topic_id_str = parts[1];
            let msg_payload = &parts[2..].join(" ");

            if let Ok(tid) = topic_id_str.parse::<u16>() {
                // Forward to each subscriber
                if let Some(subs) = topic_id_to_subs.get(&tid) {
                    let publish_msg = format!("PUBLISH {} {}", tid, msg_payload);
                    for &dest in subs {
                        // Send the publish message to each subscriber
                        let _ = socket.send_to(publish_msg.as_bytes(), dest);
                    }
                }
                // Acknowledge to the publisher
                let ack_msg = format!("PUBACK {}", tid);
                socket.send_to(ack_msg.as_bytes(), src_addr)?;
            }
        }
        else {
            // Unknown or malformed command
            let error_msg = "ERROR Unknown or malformed command";
            socket.send_to(error_msg.as_bytes(), src_addr)?;
        }
    }
}


#[cfg(feature = "client")]
fn main() -> std::io::Result<()> {
    // This client binds to an ephemeral local port
    let client_socket = UdpSocket::bind("127.0.0.1:0")?;
    client_socket.set_nonblocking(false)?;  // We'll block on recv_from

    // Hardcode the broker's address for demo
    let broker_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();

    // 1) Register a topic name
    let register_cmd = "REGISTER temperature";
    client_socket.send_to(register_cmd.as_bytes(), broker_addr)?;
    let response = receive_line(&client_socket)?;
    println!("register response: {}", response);

    // 2) Subscribe to that topic
    let subscribe_cmd = "SUBSCRIBE temperature";
    client_socket.send_to(subscribe_cmd.as_bytes(), broker_addr)?;
    let response = receive_line(&client_socket)?;
    println!("subscribe response: {}", response);

    // 3) Optionally publish something:
    //    Let's assume the broker assigned topic_id=1 above
    //    If not, parse the SUBACK to get the actual ID
    let publish_cmd = "PUBLISH 1 hello_from_client";
    client_socket.send_to(publish_cmd.as_bytes(), broker_addr)?;
    let response = receive_line(&client_socket)?;
    println!("publish response: {}", response);

    println!("Client listening for publish messages (Ctrl+C to exit)...");
    // 4) Listen forever for unsolicited messages from the broker
    loop {
        let incoming = receive_line(&client_socket)?;
        println!("Received unsolicited: {}", incoming);
    }
}

// Helper to do a blocking recv_from and convert to string
fn receive_line(socket: &UdpSocket) -> std::io::Result<String> {
    let mut buf = [0u8; 1024];
    let (len, _src) = socket.recv_from(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf[..len]).to_string())
}
