# MQTT-SN over UDP (Minimal Rust Implementation)

This project implements a minimal **MQTT-SN–style** pub/sub messaging system over **raw UDP** using **Rust**, simulating:

- A central **Broker** (`broker`) that manages topic registration, subscriptions, and message fan-out.
- A **Publisher** (`publisher`) that registers topics and publishes messages via CLI.
- A **Subscriber** (`subscriber`) that subscribes to a topic and passively listens for published messages.

This is a simplified prototype — no QoS, retries, or binary MQTT-SN wire protocol. All messages are sent as plain-text in single UDP packets.


## Usage

### 1. Start the Broker

```bash
cargo run --bin broker
```
- Binds to `0.0.0.0:5000`
- Listens for all REGISTER / SUBSCRIBE / PUBLISH commands
- Sends back REGACK / SUBACK / PUBACK responses
- Forwards published messages to all subscribers of a topic


### 2. Run a Subscriber (in a new terminal)

```bash
cargo run --bin subscriber -- <topic>
```

Example:
```bash
cargo run --bin subscriber -- temperature
```

- Binds to a random local UDP port
- Registers and subscribes to the given topic
- Waits for incoming `PUBLISH` messages
- Prints messages in the format:  
  `> PUBLISH <topic_id> <payload>`


### 3. Run a Publisher (in another terminal)

```bash
cargo run --bin publisher -- <topic> <message>
```

Example:
```bash
cargo run --bin publisher -- temperature "Hello World!"
```

- Registers the topic with the broker
- Sends a publish message with the topic ID and your message payload


## Protocol & Packet Format

All messages are sent as **UTF-8 strings** in single UDP packets. Each client uses an ephemeral port to talk to the broker (`127.0.0.1:5000`).

### Commands (Client to Broker)

| Command     | Format                                 | Description                             |
|-------------|----------------------------------------|-----------------------------------------|
| REGISTER    | `REGISTER <topic>`                     | Ask the broker to assign a topic ID     |
| SUBSCRIBE   | `SUBSCRIBE <topic>`                    | Subscribe to a topic                    |
| PUBLISH     | `PUBLISH <topic_id> <message>`         | Publish a message to a topic            |

### Responses (Broker to Client)

| Type      | Format                                 | Notes                                   |
|-----------|----------------------------------------|-----------------------------------------|
| REGACK    | `REGACK <topic> <topic_id>`            | Broker’s reply to REGISTER              |
| SUBACK    | `SUBACK <topic> <topic_id>`            | Broker’s reply to SUBSCRIBE             |
| PUBACK    | `PUBACK <topic_id>`                    | Broker’s ACK for PUBLISH                |
| PUBLISH   | `PUBLISH <topic_id> <message>`         | Sent to all subscribers of the topic    |
| ERROR     | `ERROR <message>`                      | Sent for malformed commands             |

### Example Flow

```text
# Publisher sends:
REGISTER temperature         return REGACK temperature 1
PUBLISH 1 HelloThere         return PUBACK 1

# Subscriber sends:
REGISTER temperature         return REGACK temperature 1
SUBSCRIBE temperature        return SUBACK temperature 1

# Broker sends to subscriber:
PUBLISH 1 HelloThere
```


## Assumptions

- All messages fit in a single UDP packet (no fragmentation).
- No QoS or retries — dropped packets are lost.
- No offline buffering or persistent sessions.
- Broker fans out messages using the subscriber’s `SocketAddr`.
