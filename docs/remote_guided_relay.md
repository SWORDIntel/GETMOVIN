# Remote-Guided Auto-Coding Relay Architecture

## Overview

The AI Relay service provides a secure middlebox for remote-guided auto-coding when direct connections between AI controllers and target agents are not possible (CGNAT, firewalls, etc.).

**Key Features:**
- **CNSA 2.0 Compliant**: Full Commercial National Security Algorithm Suite 2.0 compliance
- **TLS Extensions**: Command channel via TLS ALPN extensions
- **MEMSHADOW Protocol**: Binary data transmission using custom MEMSHADOW protocol
- **Multiple Transport Options**: Direct IP, FQDN (dynamic DNS), Tor (.onion)
- **Automatic Reconnection**: Resilient connection handling with exponential backoff

## Architecture

```
┌─────────────────┐         ┌──────────────┐         ┌─────────────────┐
│  AI Controller  │◄───────►│  AI Relay    │◄───────►│  Target Agent   │
│  (MILTOP/etc)   │         │   Service    │         │  (Auto-Coder)   │
└─────────────────┘         └──────────────┘         └─────────────────┘
     │                            │                            │
     │                            │                            │
     └──────── TLS (CNSA 2.0) ─────┴──────── TLS (CNSA 2.0) ─────┘
     │                            │                            │
     │ Commands: TLS Extensions   │                            │
     │ Data: MEMSHADOW Binary     │                            │
```

## CNSA 2.0 Security Specifications

### TLS Configuration

**Required:**
- TLS 1.2 or higher (TLS 1.3 preferred)
- Perfect Forward Secrecy (PFS) enabled

**Cipher Suites (Priority Order):**
1. `ECDHE-ECDSA-AES256-GCM-SHA384` (Preferred: ECDSA P-384, AES-256, SHA-384)
2. `ECDHE-RSA-AES256-GCM-SHA384` (RSA 3072+, AES-256, SHA-384)
3. `DHE-RSA-AES256-GCM-SHA384` (DH 3072+, AES-256, SHA-384)

**Key Exchange:**
- ECDH with P-384 curve (preferred)
- RSA 3072+ bits (fallback)
- DH 3072+ bits (fallback)

**Encryption:**
- AES-256-GCM (Galois/Counter Mode)

**Hashing:**
- SHA-384

**Digital Signatures:**
- ECDSA P-384 (preferred)
- RSA 3072+ (fallback)

### TLS Extensions (ALPN)

**Application-Layer Protocol Negotiation (ALPN):**
- `ai-relay-command`: Command channel (TLS extension)
- `ai-relay-memshadow`: Binary data channel (MEMSHADOW protocol)

Commands are transmitted via TLS extensions when ALPN protocol `ai-relay-command` is negotiated. All other data uses MEMSHADOW binary protocol.

## Deployment Topologies

### 1. Direct IP Connection

```
Controller → Relay (public IP:8889) → Agent
```

**Configuration:**
```yaml
# relay.yaml
listen:
  host: "0.0.0.0"
  port: 8889

# client.yaml
relay_host: "203.0.113.1"
relay_port: 8889
```

### 2. FQDN (Dynamic DNS)

```
Controller → Relay (relay.example.com:8889) → Agent
```

**Configuration:**
```yaml
# relay.yaml
listen:
  host: "0.0.0.0"
  port: 8889

# client.yaml
relay_host: "relay.example.com"
relay_port: 8889
```

**Dynamic DNS Setup:**
1. Deploy relay on public server
2. Configure dynamic DNS (e.g., DuckDNS, No-IP)
3. Point FQDN to relay IP
4. Configure clients to use FQDN

### 3. Tor Hidden Service

```
Controller → Relay (.onion:8889) → Agent
```

**Setup:**
```bash
# On relay server
sudo /opt/ai-relay/scripts/setup_tor.sh
```

**Configuration:**
```yaml
# relay.yaml
tor:
  enabled: true
  hidden_service_dir: "/var/lib/tor/ai-relay"
  hidden_service_port: 8889

# client.yaml
relay_host: "abc123def456.onion"
relay_port: 8889
use_tor: true
```

## CGNAT Scenarios

### Problem
AI controllers behind CGNAT cannot receive incoming connections, making direct agent-to-controller communication impossible.

### Solution
Use relay service as middlebox:

1. **Controller Setup:**
   - Controller connects to relay (outbound connection)
   - Relay maintains persistent connection

2. **Agent Setup:**
   - Agent connects to relay (outbound connection)
   - Relay bridges connections

3. **Communication Flow:**
   ```
   Agent → Relay → Controller (commands)
   Controller → Relay → Agent (responses)
   ```

### Configuration Example

**Relay (Public Server):**
```yaml
# /etc/ai-relay/relay.yaml
listen:
  host: "0.0.0.0"
  port: 8889
controller:
  endpoint: "ws://controller.example.com:8888"
auth:
  client_token: "agent-secret-token"
  controller_token: "controller-secret-token"
```

**Agent (Behind CGNAT):**
```yaml
# ~/.config/ai-relay/client.yaml
relay_host: "relay.example.com"
relay_port: 8889
auth_token: "agent-secret-token"
use_tls: true
```

**Controller (Behind CGNAT):**
- Connects to relay via WebSocket
- Uses controller_token for authentication

## Installation

### Debian/Ubuntu

```bash
# Clone or extract relay package
cd relay

# Run installer
sudo ./scripts/install.sh

# Configure
sudo nano /etc/ai-relay/relay.yaml

# Start service
sudo systemctl start ai-relay
sudo systemctl enable ai-relay

# Check status
sudo systemctl status ai-relay
curl http://localhost:9090/healthz
```

### Manual Installation

```bash
# Install dependencies
pip3 install -r relay/requirements.txt

# Copy files
sudo cp -r relay/src /opt/ai-relay/lib
sudo cp relay/config/relay.yaml.example /etc/ai-relay/relay.yaml

# Create user
sudo useradd -r -s /bin/false ai-relay

# Set permissions
sudo chown -R ai-relay:ai-relay /opt/ai-relay
sudo chown ai-relay:ai-relay /etc/ai-relay/relay.yaml

# Run
sudo -u ai-relay python3 /opt/ai-relay/lib/relay_daemon.py
```

## Configuration

### Relay Configuration (`/etc/ai-relay/relay.yaml`)

```yaml
# Network
listen:
  host: "0.0.0.0"
  port: 8889

# Controller endpoint
controller:
  endpoint: "ws://controller.example.com:8888"
  timeout: 30

# Authentication
auth:
  require_auth: true
  client_token: "CHANGE_ME_CLIENT_TOKEN"
  controller_token: "CHANGE_ME_CONTROLLER_TOKEN"

# TLS (CNSA 2.0)
tls:
  enabled: true
  cert_file: "/etc/ai-relay/cert.pem"
  key_file: "/etc/ai-relay/key.pem"

# Limits
limits:
  max_sessions: 100
  max_message_size: 10485760
  idle_timeout: 300
```

### Client Configuration (`~/.config/ai-relay/client.yaml`)

```yaml
# Relay connection
relay_host: "relay.example.com"
relay_port: 8889
use_tls: true

# Authentication
auth_token: "YOUR_CLIENT_TOKEN"

# Tor (optional)
use_tor: false
tor_proxy: "127.0.0.1:9050"

# Reconnection
max_reconnect_attempts: 10
reconnect_delay: 1.0
max_reconnect_delay: 60.0
```

## Certificate Management

### Self-Signed Certificate (Testing)

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/ai-relay/key.pem \
  -out /etc/ai-relay/cert.pem \
  -days 365 \
  -subj "/CN=ai-relay"
```

### Let's Encrypt (Production)

```bash
# Install certbot
sudo apt-get install certbot

# Obtain certificate
sudo certbot certonly --standalone -d relay.example.com

# Update relay.yaml
tls:
  cert_file: "/etc/letsencrypt/live/relay.example.com/fullchain.pem"
  key_file: "/etc/letsencrypt/live/relay.example.com/privkey.pem"
```

## Tor Setup

### Enable Tor Hidden Service

```bash
# Run setup script
sudo /opt/ai-relay/scripts/setup_tor.sh

# Or manually:
sudo nano /etc/tor/torrc.d/ai-relay.conf
```

**Tor Configuration:**
```
HiddenServiceDir /var/lib/tor/ai-relay
HiddenServicePort 8889 127.0.0.1:8889
```

**Restart Tor:**
```bash
sudo systemctl restart tor

# Get .onion address
sudo cat /var/lib/tor/ai-relay/hostname
```

### Client Tor Configuration

**Using torsocks:**
```bash
torsocks python3 client.py --relay-host abc123.onion
```

**Using SOCKS5 proxy:**
```yaml
# client.yaml
use_tor: true
tor_proxy: "127.0.0.1:9050"
```

## Protocol Details

### Command Channel (TLS Extensions)

Commands are transmitted via TLS ALPN extension when `ai-relay-command` protocol is negotiated.

**Command Format:**
```
+------------------+
| Command Type (1) |
+------------------+
| Sequence (4)     |
+------------------+
| Payload Len (4)  |
+------------------+
| Payload (N)      |
+------------------+
```

**Command Types:**
- `0x01`: CMD_EXECUTE
- `0x02`: CMD_CODE_GENERATE
- `0x03`: CMD_HEARTBEAT
- `0x04`: CMD_REGISTER
- `0x05`: CMD_RESPONSE
- `0x06`: CMD_ERROR

### MEMSHADOW Binary Protocol

All binary data (non-commands) uses MEMSHADOW protocol as defined in `modules/memshadow_protocol.py`.

**Protocol Features:**
- 32-byte header with magic, version, message type
- HMAC authentication
- Nonce-based replay protection
- Batch message support

## Health Checks

### Endpoints

- `/healthz`: Basic health check
- `/readyz`: Readiness check (checks session limits)
- `/metrics`: Prometheus metrics
- `/stats`: Detailed statistics

### Example

```bash
# Health check
curl http://localhost:9090/healthz

# Metrics
curl http://localhost:9090/metrics

# Statistics
curl http://localhost:9090/stats | jq
```

## Security Considerations

### Authentication

- **Required**: Both client and controller must authenticate
- **Tokens**: Use strong, randomly generated tokens
- **Rotation**: Rotate tokens regularly

### TLS

- **CNSA 2.0**: Always use CNSA 2.0 compliant cipher suites
- **Certificates**: Use proper CA-signed certificates in production
- **Verification**: Enable certificate verification

### Network Security

- **Firewall**: Restrict access to relay port
- **IP Whitelisting**: Consider IP-based access control
- **Rate Limiting**: Implement rate limiting to prevent abuse

### Logging

- **Structured Logs**: JSON format for easy parsing
- **Sensitive Data**: Never log tokens or passwords
- **Audit Trail**: Log all authentication attempts

## Troubleshooting

### Connection Issues

**Problem**: Cannot connect to relay
**Solutions**:
- Check firewall rules
- Verify relay is running: `systemctl status ai-relay`
- Check logs: `tail -f /var/log/ai-relay/relay.log`
- Verify TLS certificates

### Authentication Failures

**Problem**: Authentication failed
**Solutions**:
- Verify tokens match in config
- Check token format (no extra spaces)
- Ensure `require_auth: true` matches client config

### Tor Issues

**Problem**: Cannot connect via Tor
**Solutions**:
- Verify Tor is running: `systemctl status tor`
- Check hidden service: `sudo cat /var/lib/tor/ai-relay/hostname`
- Test Tor connection: `torsocks curl http://example.com`

### TLS Errors

**Problem**: TLS handshake failures
**Solutions**:
- Verify certificates are valid
- Check CNSA 2.0 cipher support
- Ensure TLS 1.2+ is enabled
- Review certificate expiration

## End-to-End Example

### 1. Deploy Relay

```bash
# On public server (Debian/Ubuntu)
cd relay
sudo ./scripts/install.sh
sudo nano /etc/ai-relay/relay.yaml  # Configure tokens
sudo systemctl start ai-relay
```

### 2. Configure Agent

```bash
# On target machine
mkdir -p ~/.config/ai-relay
cp config/remote_guided.yaml.example ~/.config/ai-relay/client.yaml
nano ~/.config/ai-relay/client.yaml  # Set relay_host and auth_token
```

### 3. Connect Agent

```python
from modules.relay_client import create_relay_client_from_config

client = create_relay_client_from_config()
await client.connect()

# Send command via TLS extension
await client.send_command(TLSCommandType.CMD_EXECUTE, b"command_data")

# Send MEMSHADOW binary
await client.send(memshadow_message_bytes)
```

### 4. Verify Connection

```bash
# Check relay stats
curl http://relay.example.com:9090/stats | jq

# Check logs
tail -f /var/log/ai-relay/relay.log
```

## References

- **CNSA 2.0**: Commercial National Security Algorithm Suite 2.0
- **TLS ALPN**: Application-Layer Protocol Negotiation (RFC 7301)
- **MEMSHADOW Protocol**: See `modules/memshadow_protocol.py`
- **WebSocket**: RFC 6455

## Support

For issues or questions:
1. Check logs: `/var/log/ai-relay/relay.log`
2. Review configuration: `/etc/ai-relay/relay.yaml`
3. Test connectivity: `curl http://localhost:9090/healthz`
4. Check systemd: `systemctl status ai-relay`
