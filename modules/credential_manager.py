"""Credential Manager - Persistent Credential Storage

Stores all harvested credentials, tokens, hashes, and authentication material
for reuse across sessions and operations.

Storage Location: ./loot/credentials/
- credentials.json: Main credential store
- tokens/: Kerberos tickets, access tokens
- hashes/: NTLM, LM hashes
- certificates/: Extracted certificates and keys
- sessions/: Session-specific credential dumps

Classification: Security Research / Authorized Testing Only
"""

import os
import json
import hashlib
import base64
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import shutil


class CredentialType(Enum):
    """Types of credentials"""
    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"
    LM_HASH = "lm_hash"
    KERBEROS_TGT = "kerberos_tgt"
    KERBEROS_TGS = "kerberos_tgs"
    ACCESS_TOKEN = "access_token"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    API_KEY = "api_key"
    SNMP_COMMUNITY = "snmp_community"
    DEFAULT_CRED = "default_credential"
    DPAPI_BLOB = "dpapi_blob"
    BROWSER_PASSWORD = "browser_password"
    CONFIG_SECRET = "config_secret"
    SERVICE_ACCOUNT = "service_account"


class CredentialSource(Enum):
    """Source of credential acquisition"""
    LSASS_DUMP = "lsass_dump"
    SAM_DUMP = "sam_dump"
    LSA_SECRETS = "lsa_secrets"
    CREDENTIAL_MANAGER = "credential_manager"
    KERBEROS_CACHE = "kerberos_cache"
    DPAPI = "dpapi"
    CONFIG_FILE = "config_file"
    BROWSER = "browser"
    NETWORK_CAPTURE = "network_capture"
    DEFAULT_SCAN = "default_scan"
    USER_INPUT = "user_input"
    LATERAL_MOVEMENT = "lateral_movement"
    TOKEN_MANIPULATION = "token_manipulation"
    CERTIFICATE_STORE = "certificate_store"
    REGISTRY = "registry"
    MEMORY_SCRAPE = "memory_scrape"
    VLAN_BYPASS = "vlan_bypass"


@dataclass
class Credential:
    """Single credential entry"""
    id: str  # Unique identifier
    cred_type: str  # CredentialType value
    source: str  # CredentialSource value
    username: str
    domain: str = ""
    password: str = ""
    hash_value: str = ""  # For NTLM/LM hashes
    ticket_data: str = ""  # Base64 encoded ticket/token
    target: str = ""  # Target system/service
    port: int = 0
    protocol: str = ""  # ssh, smb, winrm, rdp, etc.
    notes: str = ""
    discovered_at: str = ""
    last_used: str = ""
    valid: bool = True
    tested: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.discovered_at:
            self.discovered_at = datetime.now().isoformat()
        if not self.id:
            self.id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique ID for credential"""
        data = f"{self.cred_type}:{self.username}:{self.domain}:{self.target}:{self.hash_value}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Credential':
        """Create from dictionary"""
        return cls(**data)
    
    def get_auth_string(self) -> str:
        """Get authentication string for display"""
        if self.password:
            return f"{self.domain}\\{self.username}:{self.password}" if self.domain else f"{self.username}:{self.password}"
        elif self.hash_value:
            return f"{self.domain}\\{self.username}:{self.hash_value}" if self.domain else f"{self.username}:{self.hash_value}"
        else:
            return f"{self.domain}\\{self.username}" if self.domain else self.username


class CredentialManager:
    """Manages persistent credential storage"""
    
    DEFAULT_LOOT_DIR = Path("loot")
    CREDENTIALS_FILE = "credentials.json"
    
    def __init__(self, loot_dir: Optional[Path] = None):
        self.loot_dir = Path(loot_dir) if loot_dir else self.DEFAULT_LOOT_DIR
        self.credentials: Dict[str, Credential] = {}
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Initialize directory structure
        self._init_directories()
        
        # Load existing credentials
        self._load_credentials()
    
    def _init_directories(self):
        """Initialize loot directory structure"""
        directories = [
            self.loot_dir,
            self.loot_dir / "credentials",
            self.loot_dir / "tokens",
            self.loot_dir / "hashes",
            self.loot_dir / "certificates",
            self.loot_dir / "sessions",
            self.loot_dir / "sessions" / self.session_id,
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def _get_credentials_path(self) -> Path:
        """Get path to main credentials file"""
        return self.loot_dir / "credentials" / self.CREDENTIALS_FILE
    
    def _load_credentials(self):
        """Load credentials from disk"""
        creds_path = self._get_credentials_path()
        
        if creds_path.exists():
            try:
                with open(creds_path, 'r') as f:
                    data = json.load(f)
                    for cred_id, cred_data in data.get('credentials', {}).items():
                        self.credentials[cred_id] = Credential.from_dict(cred_data)
            except Exception as e:
                print(f"[!] Error loading credentials: {e}")
    
    def _save_credentials(self):
        """Save credentials to disk"""
        creds_path = self._get_credentials_path()
        
        data = {
            'version': '1.0',
            'last_updated': datetime.now().isoformat(),
            'session_id': self.session_id,
            'credential_count': len(self.credentials),
            'credentials': {
                cred_id: cred.to_dict() 
                for cred_id, cred in self.credentials.items()
            }
        }
        
        try:
            with open(creds_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"[!] Error saving credentials: {e}")
    
    def add_credential(self, credential: Credential) -> str:
        """Add a credential to the store"""
        # Check for duplicates
        if credential.id in self.credentials:
            # Update existing
            existing = self.credentials[credential.id]
            if credential.password and not existing.password:
                existing.password = credential.password
            if credential.hash_value and not existing.hash_value:
                existing.hash_value = credential.hash_value
            existing.last_used = datetime.now().isoformat()
            existing.metadata.update(credential.metadata)
        else:
            self.credentials[credential.id] = credential
        
        # Save to disk
        self._save_credentials()
        
        # Also save to session-specific file
        self._save_session_credential(credential)
        
        return credential.id
    
    def add_password(self, username: str, password: str, domain: str = "", 
                     target: str = "", source: str = CredentialSource.USER_INPUT.value,
                     protocol: str = "", port: int = 0, notes: str = "") -> str:
        """Add a password credential"""
        cred = Credential(
            id="",
            cred_type=CredentialType.PASSWORD.value,
            source=source,
            username=username,
            password=password,
            domain=domain,
            target=target,
            protocol=protocol,
            port=port,
            notes=notes
        )
        return self.add_credential(cred)
    
    def add_hash(self, username: str, hash_value: str, domain: str = "",
                 hash_type: str = "ntlm", target: str = "", 
                 source: str = CredentialSource.LSASS_DUMP.value) -> str:
        """Add an NTLM/LM hash"""
        cred_type = CredentialType.NTLM_HASH.value if hash_type.lower() == "ntlm" else CredentialType.LM_HASH.value
        cred = Credential(
            id="",
            cred_type=cred_type,
            source=source,
            username=username,
            hash_value=hash_value,
            domain=domain,
            target=target
        )
        return self.add_credential(cred)
    
    def add_ticket(self, username: str, ticket_data: bytes, ticket_type: str = "tgt",
                   domain: str = "", target: str = "", 
                   source: str = CredentialSource.KERBEROS_CACHE.value,
                   expires: str = "") -> str:
        """Add a Kerberos ticket"""
        cred_type = CredentialType.KERBEROS_TGT.value if ticket_type.lower() == "tgt" else CredentialType.KERBEROS_TGS.value
        
        # Base64 encode ticket data
        ticket_b64 = base64.b64encode(ticket_data).decode() if isinstance(ticket_data, bytes) else ticket_data
        
        cred = Credential(
            id="",
            cred_type=cred_type,
            source=source,
            username=username,
            domain=domain,
            target=target,
            ticket_data=ticket_b64,
            metadata={'expires': expires}
        )
        
        # Also save ticket to file
        ticket_path = self.loot_dir / "tokens" / f"{username}_{ticket_type}_{self.session_id}.kirbi"
        try:
            with open(ticket_path, 'wb') as f:
                f.write(ticket_data if isinstance(ticket_data, bytes) else base64.b64decode(ticket_data))
        except Exception:
            pass
        
        return self.add_credential(cred)
    
    def add_token(self, username: str, token_data: str, token_type: str = "access",
                  target: str = "", source: str = CredentialSource.TOKEN_MANIPULATION.value) -> str:
        """Add an access token"""
        cred = Credential(
            id="",
            cred_type=CredentialType.ACCESS_TOKEN.value,
            source=source,
            username=username,
            target=target,
            ticket_data=token_data,
            metadata={'token_type': token_type}
        )
        return self.add_credential(cred)
    
    def add_default_credential(self, username: str, password: str, vendor: str,
                               target: str = "", protocol: str = "ssh", port: int = 22,
                               success: bool = False) -> str:
        """Add a default/discovered credential from VLAN bypass scanning"""
        cred = Credential(
            id="",
            cred_type=CredentialType.DEFAULT_CRED.value,
            source=CredentialSource.DEFAULT_SCAN.value,
            username=username,
            password=password,
            target=target,
            protocol=protocol,
            port=port,
            tested=True,
            valid=success,
            metadata={'vendor': vendor}
        )
        return self.add_credential(cred)
    
    def add_ssh_key(self, username: str, key_data: str, key_type: str = "rsa",
                    passphrase: str = "", target: str = "",
                    source: str = CredentialSource.CONFIG_FILE.value) -> str:
        """Add an SSH private key"""
        cred = Credential(
            id="",
            cred_type=CredentialType.SSH_KEY.value,
            source=source,
            username=username,
            target=target,
            ticket_data=key_data,
            password=passphrase,  # Key passphrase if any
            metadata={'key_type': key_type}
        )
        
        # Save key to file
        key_path = self.loot_dir / "certificates" / f"{username}_id_{key_type}_{self.session_id}"
        try:
            with open(key_path, 'w') as f:
                f.write(key_data)
            os.chmod(key_path, 0o600)
        except Exception:
            pass
        
        return self.add_credential(cred)
    
    def add_certificate(self, subject: str, cert_data: str, key_data: str = "",
                        target: str = "", source: str = CredentialSource.CERTIFICATE_STORE.value) -> str:
        """Add a certificate"""
        cred = Credential(
            id="",
            cred_type=CredentialType.CERTIFICATE.value,
            source=source,
            username=subject,
            target=target,
            ticket_data=cert_data,
            metadata={'has_private_key': bool(key_data)}
        )
        
        # Save certificate to file
        cert_path = self.loot_dir / "certificates" / f"{subject.replace(' ', '_')}_{self.session_id}.pem"
        try:
            with open(cert_path, 'w') as f:
                f.write(cert_data)
                if key_data:
                    f.write("\n")
                    f.write(key_data)
        except Exception:
            pass
        
        return self.add_credential(cred)
    
    def add_snmp_community(self, community: str, target: str, version: str = "2c",
                           access: str = "read-only") -> str:
        """Add SNMP community string"""
        cred = Credential(
            id="",
            cred_type=CredentialType.SNMP_COMMUNITY.value,
            source=CredentialSource.NETWORK_CAPTURE.value,
            username=community,
            target=target,
            protocol="snmp",
            port=161,
            metadata={'version': version, 'access': access}
        )
        return self.add_credential(cred)
    
    def _save_session_credential(self, credential: Credential):
        """Save credential to session-specific file"""
        session_dir = self.loot_dir / "sessions" / self.session_id
        session_file = session_dir / "credentials.json"
        
        try:
            existing = {}
            if session_file.exists():
                with open(session_file, 'r') as f:
                    existing = json.load(f)
            
            if 'credentials' not in existing:
                existing['credentials'] = {}
            
            existing['credentials'][credential.id] = credential.to_dict()
            existing['last_updated'] = datetime.now().isoformat()
            
            with open(session_file, 'w') as f:
                json.dump(existing, f, indent=2, default=str)
        except Exception:
            pass
    
    def get_credential(self, cred_id: str) -> Optional[Credential]:
        """Get credential by ID"""
        return self.credentials.get(cred_id)
    
    def get_credentials_by_type(self, cred_type: CredentialType) -> List[Credential]:
        """Get all credentials of a specific type"""
        return [c for c in self.credentials.values() if c.cred_type == cred_type.value]
    
    def get_credentials_by_target(self, target: str) -> List[Credential]:
        """Get all credentials for a specific target"""
        return [c for c in self.credentials.values() if target.lower() in c.target.lower()]
    
    def get_credentials_by_domain(self, domain: str) -> List[Credential]:
        """Get all credentials for a specific domain"""
        return [c for c in self.credentials.values() if domain.lower() in c.domain.lower()]
    
    def get_valid_credentials(self) -> List[Credential]:
        """Get all validated credentials"""
        return [c for c in self.credentials.values() if c.valid and c.tested]
    
    def get_passwords(self) -> List[Credential]:
        """Get all password credentials"""
        return self.get_credentials_by_type(CredentialType.PASSWORD)
    
    def get_hashes(self) -> List[Credential]:
        """Get all hash credentials (NTLM + LM)"""
        ntlm = self.get_credentials_by_type(CredentialType.NTLM_HASH)
        lm = self.get_credentials_by_type(CredentialType.LM_HASH)
        return ntlm + lm
    
    def get_tickets(self) -> List[Credential]:
        """Get all Kerberos tickets"""
        tgt = self.get_credentials_by_type(CredentialType.KERBEROS_TGT)
        tgs = self.get_credentials_by_type(CredentialType.KERBEROS_TGS)
        return tgt + tgs
    
    def get_all(self) -> List[Credential]:
        """Get all credentials"""
        return list(self.credentials.values())
    
    def mark_as_used(self, cred_id: str):
        """Mark credential as recently used"""
        if cred_id in self.credentials:
            self.credentials[cred_id].last_used = datetime.now().isoformat()
            self._save_credentials()
    
    def mark_as_valid(self, cred_id: str, valid: bool = True):
        """Mark credential as tested and valid/invalid"""
        if cred_id in self.credentials:
            self.credentials[cred_id].tested = True
            self.credentials[cred_id].valid = valid
            self._save_credentials()
    
    def remove_credential(self, cred_id: str) -> bool:
        """Remove a credential"""
        if cred_id in self.credentials:
            del self.credentials[cred_id]
            self._save_credentials()
            return True
        return False
    
    def export_hashcat(self, output_path: Optional[Path] = None) -> Path:
        """Export hashes in hashcat format"""
        output_path = output_path or (self.loot_dir / "hashes" / f"hashes_{self.session_id}.txt")
        
        hashes = self.get_hashes()
        with open(output_path, 'w') as f:
            for h in hashes:
                if h.cred_type == CredentialType.NTLM_HASH.value:
                    # NTLM format: user:id:lm:ntlm:::
                    f.write(f"{h.username}:::{h.hash_value}:::\n")
                elif h.cred_type == CredentialType.LM_HASH.value:
                    f.write(f"{h.username}:{h.hash_value}::::\n")
        
        return output_path
    
    def export_secretsdump(self, output_path: Optional[Path] = None) -> Path:
        """Export in secretsdump format"""
        output_path = output_path or (self.loot_dir / "hashes" / f"secretsdump_{self.session_id}.txt")
        
        hashes = self.get_hashes()
        with open(output_path, 'w') as f:
            for h in hashes:
                domain = h.domain or "WORKGROUP"
                f.write(f"{domain}\\{h.username}:{h.hash_value}\n")
        
        return output_path
    
    def export_credentials_csv(self, output_path: Optional[Path] = None) -> Path:
        """Export credentials as CSV"""
        output_path = output_path or (self.loot_dir / "credentials" / f"credentials_{self.session_id}.csv")
        
        import csv
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Domain', 'Username', 'Password/Hash', 'Target', 'Protocol', 'Port', 'Valid', 'Source'])
            
            for cred in self.credentials.values():
                secret = cred.password or cred.hash_value or "[token/key]"
                writer.writerow([
                    cred.cred_type,
                    cred.domain,
                    cred.username,
                    secret,
                    cred.target,
                    cred.protocol,
                    cred.port,
                    cred.valid,
                    cred.source
                ])
        
        return output_path
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of stored credentials"""
        summary = {
            'total': len(self.credentials),
            'by_type': {},
            'by_source': {},
            'valid': len([c for c in self.credentials.values() if c.valid]),
            'tested': len([c for c in self.credentials.values() if c.tested]),
            'domains': list(set(c.domain for c in self.credentials.values() if c.domain)),
            'targets': list(set(c.target for c in self.credentials.values() if c.target))[:20],
        }
        
        # Count by type
        for cred in self.credentials.values():
            summary['by_type'][cred.cred_type] = summary['by_type'].get(cred.cred_type, 0) + 1
            summary['by_source'][cred.source] = summary['by_source'].get(cred.source, 0) + 1
        
        return summary
    
    def print_summary(self):
        """Print credential summary to console"""
        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box
            
            console = Console()
            summary = self.get_summary()
            
            console.print(f"\n[bold cyan]Credential Store Summary[/bold cyan]")
            console.print(f"Location: {self.loot_dir / 'credentials'}")
            console.print(f"Total Credentials: {summary['total']}")
            console.print(f"Valid/Tested: {summary['valid']}/{summary['tested']}")
            
            if summary['by_type']:
                table = Table(title="Credentials by Type", box=box.SIMPLE)
                table.add_column("Type", style="cyan")
                table.add_column("Count", style="green", justify="right")
                
                for cred_type, count in sorted(summary['by_type'].items()):
                    table.add_row(cred_type, str(count))
                
                console.print(table)
            
            if summary['domains']:
                console.print(f"\nDomains: {', '.join(summary['domains'][:10])}")
            
        except ImportError:
            print(f"\nCredential Store Summary")
            print(f"Total: {len(self.credentials)}")


# Global credential manager instance
_credential_manager: Optional[CredentialManager] = None


def get_credential_manager(loot_dir: Optional[Path] = None) -> CredentialManager:
    """Get or create the global credential manager"""
    global _credential_manager
    
    if _credential_manager is None:
        _credential_manager = CredentialManager(loot_dir)
    
    return _credential_manager


def save_credential(username: str, password: str = "", hash_value: str = "",
                   domain: str = "", target: str = "", source: str = "",
                   cred_type: str = "", **kwargs) -> str:
    """Convenience function to save a credential"""
    manager = get_credential_manager()
    
    if password and not cred_type:
        return manager.add_password(username, password, domain, target, source or CredentialSource.USER_INPUT.value, **kwargs)
    elif hash_value:
        return manager.add_hash(username, hash_value, domain, target=target, source=source or CredentialSource.LSASS_DUMP.value)
    else:
        cred = Credential(
            id="",
            cred_type=cred_type or CredentialType.PASSWORD.value,
            source=source or CredentialSource.USER_INPUT.value,
            username=username,
            password=password,
            hash_value=hash_value,
            domain=domain,
            target=target,
            **kwargs
        )
        return manager.add_credential(cred)


def get_credentials_for_target(target: str) -> List[Credential]:
    """Get all credentials that might work for a target"""
    manager = get_credential_manager()
    return manager.get_credentials_by_target(target)
