# SODT-Server

The SODT-Server is the meeting point for clients using the SODT-Protocol. A
client connects to the server so it can find other clients. 
The server then relays sent packets between the two clients.

The server is not a storage service: It does not save, inspect, or retain sent
data. Data is relayed only while the clients are connected.

## How it works
1. Clients connect to the server and authenticate its identity.
2. The server helps the clients find each other by sending a `ClientList`-Package
3. Encrypted packets are relayed between the clients.
4. Clients can disconnect when they are finished. Otherwise the Server disconnects Clients automatically that stop sending periodic pings.

## Features
- Supports connections and disconnections of SODT-Clients.
- The Server uses ECDSA to prove the server's authenticity to connecting clients.
- The connection between the Server and a client is encrpyted with AES-GCM.
- Removes inactive clients that do not send periodic pings.

## Run with Docker Compose

Make sure [Docker](https://docs.docker.com/get-docker/) and Docker Compose are
installed. 

The server's ECDSA certificates are stored in the
`sodt-certificates` Docker volume, so they persist across container restarts.

**Example compose.yaml file**
```docker
﻿services:
  sodt-server:
    image: ghcr.io/sodt-project/sodt-server:latest
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "45645:45645"
    volumes:
      - sodt-certificates:/app/certs
    restart: unless-stopped

volumes:
  sodt-certificates:
```

You can also run it from the repository root:
```bash
cd SODT-Server
docker compose up -d --build
```

The server listens on TCP port `45645`. To view its logs:

```bash
docker compose logs -f
```

To stop the server:

```bash
docker compose down
```
