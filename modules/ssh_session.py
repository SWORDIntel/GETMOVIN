"""SSH Session Management

Manages SSH connections for remote command execution.
Allows the toolkit to work over SSH by executing commands on remote systems.
"""

from typing import Optional, Dict, List
from dataclasses import dataclass
from modules.credential_manager import get_credential_manager, CredentialType


@dataclass
class SSHSession:
    """SSH session configuration"""
    host: str
    user: Optional[str] = None
    key_file: Optional[str] = None
    password: Optional[str] = None
    port: int = 22
    active: bool = False
    
    def __str__(self):
        auth = f"{self.user}@" if self.user else ""
        return f"ssh://{auth}{self.host}:{self.port}"


class SSHSessionManager:
    """Manage SSH sessions for remote execution"""
    
    def __init__(self):
        self.sessions: Dict[str, SSHSession] = {}
        self.active_session: Optional[str] = None
        self.cred_manager = get_credential_manager()
    
    def create_session(self, name: str, host: str, user: Optional[str] = None,
                      key_file: Optional[str] = None, password: Optional[str] = None,
                      port: int = 22) -> SSHSession:
        """Create a new SSH session"""
        session = SSHSession(
            host=host,
            user=user,
            key_file=key_file,
            password=password,
            port=port
        )
        self.sessions[name] = session
        return session
    
    def create_session_from_credentials(self, name: str, host: str, 
                                       credential_id: Optional[str] = None) -> Optional[SSHSession]:
        """Create SSH session using stored credentials"""
        # Try to find SSH credentials for this host
        if credential_id:
            cred = self.cred_manager.get_credential(credential_id)
        else:
            # Look for SSH key credentials
            creds = self.cred_manager.get_credentials_by_target(host)
            ssh_creds = [c for c in creds if c.cred_type == CredentialType.SSH_KEY.value]
            if ssh_creds:
                cred = ssh_creds[0]
            else:
                # Try password credentials
                password_creds = [c for c in creds if c.cred_type == CredentialType.PASSWORD.value]
                cred = password_creds[0] if password_creds else None
        
        if not cred:
            return None
        
        # Create session
        if cred.cred_type == CredentialType.SSH_KEY.value:
            # SSH key authentication
            session = SSHSession(
                host=host,
                user=cred.username,
                key_file=cred.metadata.get('key_file') if isinstance(cred.metadata, dict) else None,
                port=cred.port or 22
            )
        else:
            # Password authentication
            session = SSHSession(
                host=host,
                user=cred.username,
                password=cred.password,
                port=cred.port or 22
            )
        
        self.sessions[name] = session
        return session
    
    def activate_session(self, name: str) -> bool:
        """Activate a session for use"""
        if name in self.sessions:
            self.active_session = name
            self.sessions[name].active = True
            return True
        return False
    
    def get_active_session(self) -> Optional[SSHSession]:
        """Get the currently active SSH session"""
        if self.active_session and self.active_session in self.sessions:
            return self.sessions[self.active_session]
        return None
    
    def list_sessions(self) -> List[str]:
        """List all session names"""
        return list(self.sessions.keys())
    
    def remove_session(self, name: str) -> bool:
        """Remove a session"""
        if name in self.sessions:
            if self.active_session == name:
                self.active_session = None
            del self.sessions[name]
            return True
        return False


# Global SSH session manager
_ssh_manager: Optional[SSHSessionManager] = None


def get_ssh_manager() -> SSHSessionManager:
    """Get global SSH session manager"""
    global _ssh_manager
    if _ssh_manager is None:
        _ssh_manager = SSHSessionManager()
    return _ssh_manager
