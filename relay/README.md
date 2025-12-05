# AI Relay Service - CNSA 2.0 Compliant Relay for Remote-Guided Auto-Coding

## Overview

The AI Relay service provides a secure, CNSA 2.0 compliant middlebox for remote-guided auto-coding when direct connections between AI controllers and target agents are not possible.

## Features

- ✅ **CNSA 2.0 Compliant**: Full Commercial National Security Algorithm Suite 2.0 compliance
- ✅ **DSSSL Integration**: Uses SWORDIntel's secure OpenSSL fork for enhanced security
- ✅ **TLS Extensions**: Command channel via TLS ALPN extensions
- ✅ **MEMSHADOW Protocol**: Binary data transmission using custom MEMSHADOW protocol
- ✅ **Multiple Transport**: Direct IP, FQDN (dynamic DNS), Tor (.onion)
- ✅ **Automatic Reconnection**: Resilient connection handling
- ✅ **Health Checks**: `/healthz`, `/readyz`, `/metrics` endpoints
- ✅ **Structured Logging**: JSON format logs
- ✅ **Debian/Ubuntu Ready**: Complete installation package

## Quick Start

### Installation

**Recommended: Install DSSSL first for enhanced security**

```bash
# Install DSSSL (secure OpenSSL fork)
sudo bash relay/scripts/install_dsssl.sh

# Install relay service (will automatically use DSSSL)
cd relay
sudo ./scripts/install.sh
sudo nano /etc/ai-relay/relay.yaml  # Configure tokens
sudo systemctl start ai-relay
```

**Note:** The relay installer automatically detects and uses DSSSL if available, falling back to standard OpenSSL if not found.

### Configuration

Edit `/etc/ai-relay/relay.yaml`:

```yaml
auth:
  client_token: "your-client-token"
  controller_token: "your-controller-token"

tls:
  enabled: true
  cert_file: "/etc/ai-relay/cert.pem"
  key_file: "/etc/ai-relay/key.pem"
```

### Client Configuration

Create `~/.config/ai-relay/client.yaml`:

```yaml
relay_host: "relay.example.com"
relay_port: 8889
auth_token: "your-client-token"
use_tls: true
```

## CNSA 2.0 Security

### Cipher Suites

- `ECDHE-ECDSA-AES256-GCM-SHA384` (Preferred: P-384, AES-256, SHA-384)
- `ECDHE-RSA-AES256-GCM-SHA384` (RSA 3072+, AES-256, SHA-384)
- `DHE-RSA-AES256-GCM-SHA384` (DH 3072+, AES-256, SHA-384)

### TLS Extensions

- **ALPN Protocol**: `ai-relay-command` for command channel
- **ALPN Protocol**: `ai-relay-memshadow` for binary data

Commands use TLS extensions, binary data uses MEMSHADOW protocol.

## Architecture

```
AI Controller ←→ Relay Service ←→ Target Agent
     (TLS + ALPN)      (TLS + ALPN)
```

## Documentation

See `docs/remote_guided_relay.md` for complete documentation.

## License

For authorized security testing only.
