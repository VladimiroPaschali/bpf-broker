import socket
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--topic', type=str, required=True, help='Topic to subscribe to')
    parser.add_argument('--bind-port', type=int, required=True, help='Local port to bind')
    parser.add_argument('--broker-ip', type=str, default='10.10.1.1', help='Broker IP address')
    parser.add_argument('--broker-port', type=int, default=11211, help='Broker port')
    args = parser.parse_args()

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Bind to fixed port
    sock.bind(('', args.bind_port))
    print(f"[+] Bound to port {args.bind_port}")

    # Send SUBSCRIBE message to broker
    msg = f"SUBSCRIBE {args.topic}"
    sock.sendto(msg.encode(), (args.broker_ip, args.broker_port))
    print(f"[+] Sent: {msg} → {args.broker_ip}:{args.broker_port}")

    # Receive published messages
    print("[+] Listening for incoming messages...")
    while True:
        data, addr = sock.recvfrom(4096)
        print(f"[<] Received from {addr}: {data.decode().strip()}")

if __name__ == "__main__":
    main()
