# Secure ATC Communication System

A secure Air Traffic Control (ATC) communication simulator built using Python, TCP sockets, and multithreading. The system enables real-time communication between multiple aircraft clients and a centralized ATC server while implementing security mechanisms to protect against common network attacks.

## Features

* Real-time communication between multiple aircraft and ATC server
* Multi-client support using TCP sockets and multithreading
* HMAC-SHA256 based message authentication
* Timestamp validation and nonce-based replay attack prevention
* Rate limiting and temporary blacklisting
* Request validation and attack monitoring
* Priority-based landing, takeoff, and gate allocation workflows
* Concurrent request handling using synchronized queues and semaphores
* Security testing through spoofing and flooding attack simulations

## Technologies Used

* Python
* TCP Sockets
* Multithreading
* HMAC-SHA256
* Queues & Semaphores
* Network Security Concepts

## Project Structure

```text
.
├── server.py
├── aircraft.py
├── secrets/
│   ├── shared_key.txt
│   └── nonces.json
├── utils/
├── logs/
└── README.md
```

## Security Mechanisms

### Authentication

Messages are authenticated using HMAC-SHA256 to ensure integrity and prevent tampering.

### Replay Protection

Timestamp validation and nonce tracking prevent attackers from reusing previously transmitted messages.

### DoS Mitigation

The server implements:

* Rate limiting
* Request validation
* Temporary blacklisting
* Attack monitoring

### Spoofing Prevention

Only authenticated aircraft with valid credentials can communicate with the ATC server.

## Workflow

1. Aircraft connects to the ATC server.
2. Request is authenticated and validated.
3. Server verifies timestamp and nonce.
4. Request is processed based on priority.
5. Landing, takeoff, or gate allocation decision is returned.
6. Security events are logged for monitoring.

## Running the Project

### Prerequisites

* Python 3.9+
* Required dependencies installed

### Start the Server

```bash
python server.py
```

### Start an Aircraft Client

```bash
python aircraft.py
```

Run multiple client instances to simulate multiple aircraft communicating with the server.

## Learning Outcomes

This project demonstrates:

* Network programming using TCP sockets
* Concurrent systems using multithreading
* Secure communication design
* Authentication and replay protection techniques
* Basic denial-of-service mitigation strategies
* Resource allocation and synchronization concepts

## Future Improvements

* TLS-based encrypted communication
* Graphical monitoring dashboard
* Persistent database integration
* Advanced scheduling algorithms
* Distributed ATC server architecture

```
```
