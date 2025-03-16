use std::net::UdpSocket;
use std::env;
use std::io;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: publisher <topic> <message>");
        return Ok(());
    }

    let topic = &args[1];
    let message = &args[2];
    let broker_addr = "127.0.0.1:5000";
    let socket = UdpSocket::bind("127.0.0.1:0")?;

    // Register topic
    socket.send_to(format!("REGISTER {}", topic).as_bytes(), broker_addr)?;
    let regack = recv_msg(&socket)?;
    println!("Registered: {}", regack);

    // Extract topic_id from REGACK
    let topic_id: u16 = regack
        .split_whitespace()
        .nth(2)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    // Publish
    socket.send_to(format!("PUBLISH {} {}", topic_id, message).as_bytes(), broker_addr)?;
    let ack = recv_msg(&socket)?;
    println!("Published: {}", ack);
    Ok(())
}

fn recv_msg(socket: &UdpSocket) -> io::Result<String> {
    let mut buf = [0u8; 1024];
    let (len, _) = socket.recv_from(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf[..len]).to_string())
}
