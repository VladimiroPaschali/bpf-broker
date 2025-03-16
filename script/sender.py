import socket
import random
import string
import argparse
import time

def generate_random_payload(length):
    return ''.join(random.choices(string.ascii_letters, k=length)).encode('utf-8')

def main():
    parser = argparse.ArgumentParser(description="Send UDP packets with random payloads.")
    parser.add_argument('--size', type=int, default=256, help='Number of bytes per packet')
    parser.add_argument('--count', type=int, default=10, help='Number of packets to send')
    parser.add_argument('--ip', type=str, default='10.10.1.1', help='Destination IP address')
    parser.add_argument('--port', type=int, default=11211, help='Destination UDP port')
    parser.add_argument('--delay', type=float, default=1, help='Delay between packets in seconds')

    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for i in range(args.count):
        payload = generate_random_payload(args.size)
        sock.sendto(payload, (args.ip, args.port))
        print(f"[{i+1}/{args.count}] Sent {args.size} bytes to {args.ip}:{args.port}")
        time.sleep(args.delay)

    sock.close()

if __name__ == "__main__":
    main()
