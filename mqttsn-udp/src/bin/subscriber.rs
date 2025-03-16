use std::net::UdpSocket;
use std::env;
use std::io;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: subscriber <topic>");
        return Ok(());
    }

    let topic = &args[1];
    let broker_addr = "127.0.0.1:5000";
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_nonblocking(false)?;

    // Register topic
    socket.send_to(format!("REGISTER {}", topic).as_bytes(), broker_addr)?;
    let _ = recv_msg(&socket)?;

    // Subscribe
    socket.send_to(format!("SUBSCRIBE {}", topic).as_bytes(), broker_addr)?;
    let suback = recv_msg(&socket)?;
    println!("Subscribed: {}", suback);

    println!("Listening for published messages...");
    loop {
        let msg = recv_msg(&socket)?;
        println!("> {}", msg);
    }
}

fn recv_msg(socket: &UdpSocket) -> io::Result<String> {
    let mut buf = [0u8; 1024];
    let (len, _) = socket.recv_from(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf[..len]).to_string())
}
