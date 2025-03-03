import socket

UDP_IP = "0.0.0.0"
UDP_PORT = 11211

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"Listening for UDP packets on port {UDP_PORT}...")

while True:
    data, addr = sock.recvfrom(4096)
    print(f"\nReceived packet from {addr}")

    hex_data = " ".join(f"{byte:02x}" for byte in data)
    print(f"Hex: {hex_data}")

    try:
        print(f"ASCII: {data.decode('utf-8', errors='ignore')}")
    except UnicodeDecodeError:
        print("Received non-printable characters.")

    # Send acknowledgment
    response = b"ACK: Received your message"
    sock.sendto(response, addr)
    print(f"Sent acknowledgment to {addr}")
