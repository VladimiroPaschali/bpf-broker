use std::net::UdpSocket;
use std::str;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:11211")?;
    println!("Listening for UDP packets on port 11211...");

    let mut buf = [0u8; 4096];

    loop {
        let (amt, src) = socket.recv_from(&mut buf)?;
        let response = &buf[..amt];
        socket.send_to(response, &src)?;
    }
}