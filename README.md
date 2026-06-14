BastionCore
============

Overview
--------
BastionCore is a lightweight endpoint detection & response (EDR) demo written in Go. It demonstrates secure agent-to-server telemetry over mTLS gRPC, storage in ClickHouse, and visualization in Grafana. The project is designed for demos and learning rather than production use.

Architecture
------------
Plain-text diagram:

Agent -> gRPC (mTLS) -> Server -> ClickHouse -> Grafana
							 \
							  -> Ollama LLM (analysis)

Stack
-----
- Go (gRPC)
- ClickHouse (time-series storage)
- Grafana (dashboarding)
- OpenSSL (local certificate generation)

Setup Instructions
------------------
1. Generate certificates (self-signed CA, server and client certs):

# Generate a self-signed CA
openssl genrsa -out certs/ca-key.pem 4096
openssl req -x509 -new -nodes -key certs/ca-key.pem -sha256 -days 3650 -out certs/ca-cert.pem -subj "/CN=BastionCore-CA"

# Server key/csr and sign
openssl genrsa -out certs/server-key.pem 2048
openssl req -new -key certs/server-key.pem -out certs/server.csr -subj "/CN=bastioncore-server"
openssl x509 -req -in certs/server.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/server-cert.pem -days 365 -sha256

# Agent (client) key/csr and sign
openssl genrsa -out certs/agent-key.pem 2048
openssl req -new -key certs/agent-key.pem -out certs/agent.csr -subj "/CN=agent-01"
openssl x509 -req -in certs/agent.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/agent-cert.pem -days 365 -sha256

Note: These commands write files into the `certs/` directory used by the demo. Adjust CNs as needed.

2. Start ClickHouse (example using Docker):

```bash
docker run -d --name clickhouse-server -p 8123:8123 -p 9000:9000 clickhouse/clickhouse-server:latest
```

3. Set the ClickHouse DSN and run the server in Codespaces:

```bash
export CLICKHOUSE_DSN="tcp://127.0.0.1:9000?username=default&password=&database=default"
go run ./cmd/server
```

4. Run the agent (in another terminal):

```bash
go run ./cmd/agent
```

How to Run
----------
- Server gRPC (mTLS): listens on `:50051` and requires client certificates signed by your CA.
- REST API: `:8080` (response actions endpoints used by demo).
- Grafana: connect to ClickHouse and import dashboard from `grafana/dashboards/`.

Screenshots
-----------

Future Work
-----------
- Agent-side command polling and secure execution for response actions.
- Authentication/authorization for REST API and gRPC beyond mTLS.
- Harden ClickHouse schema and migrations.
- Add integration tests and CI for cert generation and local runs.

OpenSSL commands
----------------
(See Setup above) — quick copy:

openssl genrsa -out certs/ca-key.pem 4096
openssl req -x509 -new -nodes -key certs/ca-key.pem -sha256 -days 3650 -out certs/ca-cert.pem -subj "/CN=BastionCore-CA"
openssl genrsa -out certs/server-key.pem 2048
openssl req -new -key certs/server-key.pem -out certs/server.csr -subj "/CN=bastioncore-server"
openssl x509 -req -in certs/server.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/server-cert.pem -days 365 -sha256
openssl genrsa -out certs/agent-key.pem 2048
openssl req -new -key certs/agent-key.pem -out certs/agent.csr -subj "/CN=agent-01"
openssl x509 -req -in certs/agent.csr -CA certs/ca-cert.pem -CAkey certs/ca-key.pem -CAcreateserial -out certs/agent-cert.pem -days 365 -sha256

