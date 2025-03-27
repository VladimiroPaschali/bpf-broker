import socket
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--topic', required=True, help='Topic to register')
    parser.add_argument('--broker-ip', default='10.10.1.1', help='Broker IP address')
    parser.add_argument('--broker-port', type=int, default=11211, help='Broker UDP port')
    args = parser.parse_args()

    msg = f"REGISTER {args.topic}"
    broker = (args.broker_ip, args.broker_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)

    print(f"[>] Sending: {msg}")
    sock.sendto(msg.encode(), broker)

    try:
        data, _ = sock.recvfrom(1024)
        print(f"[✓] Broker responded: {data.decode().strip()}")
    except socket.timeout:
        print("[!] No response from broker (timeout)")

    sock.close()

if __name__ == "__main__":
    main()
