"""LLM Remote Agent Module - Self-Coding Execution System"""

import struct
import socket
import threading
import json
import subprocess
import tempfile
import os
import sys
from typing import Optional, Dict, Any, Tuple
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import box
from rich.console import Console
from modules.utils import execute_powershell, execute_cmd, validate_target


class BinaryProtocol:
    """Custom 2-way binary protocol handler"""
    
    # Protocol constants
    MAGIC = b'\xAA\xBB\xCC\xDD'
    VERSION = 1
    
    # Message types
    MSG_COMMAND = 0x01
    MSG_CODE_GENERATE = 0x02
    MSG_EXECUTE = 0x03
    MSG_RESPONSE = 0x04
    MSG_ERROR = 0x05
    MSG_HEARTBEAT = 0x06
    
    @staticmethod
    def pack_message(msg_type: int, payload: bytes) -> bytes:
        """Pack a message into binary format"""
        # Format: MAGIC (4) + VERSION (1) + TYPE (1) + LENGTH (4) + PAYLOAD (N)
        length = len(payload)
        return struct.pack('!4sBBL', BinaryProtocol.MAGIC, BinaryProtocol.VERSION, msg_type, length) + payload
    
    @staticmethod
    def unpack_message(data: bytes) -> Tuple[int, bytes]:
        """Unpack a message from binary format"""
        if len(data) < 10:
            raise ValueError("Message too short")
        
        magic, version, msg_type, length = struct.unpack('!4sBBL', data[:10])
        
        if magic != BinaryProtocol.MAGIC:
            raise ValueError(f"Invalid magic: {magic.hex()}")
        
        if version != BinaryProtocol.VERSION:
            raise ValueError(f"Unsupported version: {version}")
        
        payload = data[10:10+length]
        if len(payload) != length:
            raise ValueError(f"Payload length mismatch: expected {length}, got {len(payload)}")
        
        return msg_type, payload
    
    @staticmethod
    def encode_json(data: Dict[str, Any]) -> bytes:
        """Encode JSON data to bytes"""
        return json.dumps(data).encode('utf-8')
    
    @staticmethod
    def decode_json(data: bytes) -> Dict[str, Any]:
        """Decode bytes to JSON data"""
        return json.loads(data.decode('utf-8'))


class CodeGenerator:
    """Code generation and execution engine"""
    
    # Safety: Blocked dangerous operations
    DANGEROUS_PATTERNS = [
        'rm -rf', 'del /f /s /q', 'format', 'fdisk',
        '__import__', 'eval(', 'exec(', 'compile(',
        'subprocess', 'os.system', 'os.popen',
        'Remove-Item -Recurse -Force', 'Format-Volume'
    ]
    
    def __init__(self, console: Console, session_data: dict):
        self.console = console
        self.session_data = session_data
        self.temp_dir = tempfile.mkdtemp(prefix='llm_agent_')
        self.execution_history = []
        self.safety_enabled = True
        
    def _check_safety(self, code: str) -> Tuple[bool, str]:
        """Check if code contains dangerous patterns"""
        if not self.safety_enabled:
            return True, ""
        
        code_lower = code.lower()
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern.lower() in code_lower:
                return False, f"Dangerous pattern detected: {pattern}"
        
        return True, ""
    
    def generate_code(self, spec: Dict[str, Any]) -> Tuple[str, str]:
        """
        Generate code based on specification
        
        Args:
            spec: Dictionary containing:
                - language: 'python', 'powershell', 'batch', etc.
                - description: What the code should do
                - requirements: List of requirements
                - imports: List of imports needed
        
        Returns:
            Tuple of (code, file_path)
        """
        language = spec.get('language', 'python').lower()
        description = spec.get('description', '')
        requirements = spec.get('requirements', [])
        imports = spec.get('imports', [])
        
        # Safety check on description
        if self.safety_enabled:
            safe, error = self._check_safety(description)
            if not safe:
                raise ValueError(f"Safety check failed: {error}")
        
        # Generate code based on language
        if language == 'python':
            code = self._generate_python(description, requirements, imports)
        elif language == 'powershell':
            code = self._generate_powershell(description, requirements, imports)
        elif language == 'batch':
            code = self._generate_batch(description, requirements, imports)
        else:
            raise ValueError(f"Unsupported language: {language}")
        
        # Save to temporary file
        ext = {
            'python': '.py',
            'powershell': '.ps1',
            'batch': '.bat'
        }.get(language, '.txt')
        
        # Safety check on generated code
        if self.safety_enabled:
            safe, error = self._check_safety(code)
            if not safe:
                raise ValueError(f"Safety check failed on generated code: {error}")
        
        file_path = os.path.join(self.temp_dir, f'generated_{len(self.execution_history)}{ext}')
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(code)
        
        self.execution_history.append({
            'file_path': file_path,
            'language': language,
            'description': description
        })
        
        return code, file_path
    
    def _generate_python(self, description: str, requirements: list, imports: list) -> str:
        """Generate Python code"""
        code_lines = []
        
        # Add imports
        if imports:
            code_lines.extend(imports)
        else:
            code_lines.append("import os")
            code_lines.append("import sys")
        
        code_lines.append("")
        code_lines.append("# Generated code")
        code_lines.append(f"# Description: {description}")
        code_lines.append("")
        
        # Add requirements as comments
        if requirements:
            code_lines.append("# Requirements:")
            for req in requirements:
                code_lines.append(f"# - {req}")
            code_lines.append("")
        
        # Generate basic structure
        code_lines.append("def main():")
        code_lines.append(f"    \"\"\"{description}\"\"\"")
        code_lines.append("    # TODO: Implement functionality")
        code_lines.append("    print('Generated code executed')")
        code_lines.append("    return 0")
        code_lines.append("")
        code_lines.append("if __name__ == '__main__':")
        code_lines.append("    sys.exit(main())")
        
        return '\n'.join(code_lines)
    
    def _generate_powershell(self, description: str, requirements: list, imports: list) -> str:
        """Generate PowerShell code"""
        code_lines = []
        
        code_lines.append("# Generated PowerShell script")
        code_lines.append(f"# Description: {description}")
        code_lines.append("")
        
        if requirements:
            code_lines.append("# Requirements:")
            for req in requirements:
                code_lines.append(f"# - {req}")
            code_lines.append("")
        
        code_lines.append("function Main {")
        code_lines.append(f"    <# {description} #>")
        code_lines.append("    Write-Host 'Generated PowerShell script executed'")
        code_lines.append("    return 0")
        code_lines.append("}")
        code_lines.append("")
        code_lines.append("Main")
        
        return '\n'.join(code_lines)
    
    def _generate_batch(self, description: str, requirements: list, imports: list) -> str:
        """Generate Batch script"""
        code_lines = []
        
        code_lines.append("@echo off")
        code_lines.append(f"REM Generated Batch script")
        code_lines.append(f"REM Description: {description}")
        code_lines.append("")
        
        if requirements:
            code_lines.append("REM Requirements:")
            for req in requirements:
                code_lines.append(f"REM - {req}")
            code_lines.append("")
        
        code_lines.append("echo Generated Batch script executed")
        code_lines.append("exit /b 0")
        
        return '\n'.join(code_lines)
    
    def execute_code(self, file_path: str, language: str, args: list = None) -> Tuple[int, str, str]:
        """
        Execute generated code
        
        Args:
            file_path: Path to code file
            language: Language of the code
            args: Additional arguments
        
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        args = args or []
        lab_use = self.session_data.get('LAB_USE', 0)
        
        # Safety check: Read and validate code before execution
        if self.safety_enabled and os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code_content = f.read()
                
                safe, error = self._check_safety(code_content)
                if not safe:
                    return 1, "", f"Safety check failed: {error}"
            except Exception as e:
                return 1, "", f"Safety check error: {e}"
        
        try:
            if language == 'python':
                cmd = [sys.executable, file_path] + args
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=self.temp_dir
                )
                return result.returncode, result.stdout, result.stderr
            
            elif language == 'powershell':
                ps_cmd = f"& '{file_path}' {' '.join(args)}"
                return execute_powershell(ps_cmd, lab_use=lab_use)
            
            elif language == 'batch':
                cmd = [file_path] + args
                return execute_cmd(' '.join(cmd), lab_use=lab_use)
            
            else:
                return 1, "", f"Unsupported language: {language}"
        
        except subprocess.TimeoutExpired:
            return 1, "", "Execution timed out after 30 seconds"
        except Exception as e:
            return 1, "", str(e)
    
    def cleanup(self):
        """Clean up temporary files"""
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except Exception:
            pass


class LLMAgentServer:
    """LLM Agent Server - Receives commands and executes them"""
    
    def __init__(self, console: Console, session_data: dict, host: str = 'localhost', port: int = 8888):
        self.console = console
        self.session_data = session_data
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.code_generator = CodeGenerator(console, session_data)
        self.client_connections = []
        
    def start(self):
        """Start the LLM agent server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            self.console.print(f"[green]LLM Agent Server started on {self.host}:{self.port}[/green]")
            
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    self.console.print(f"[cyan]New connection from {address}[/cyan]")
                    
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    self.client_connections.append(client_thread)
                
                except Exception as e:
                    if self.running:
                        self.console.print(f"[red]Error accepting connection: {e}[/red]")
        
        except Exception as e:
            self.console.print(f"[red]Failed to start server: {e}[/red]")
            self.running = False
    
    def stop(self):
        """Stop the LLM agent server"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        self.code_generator.cleanup()
        self.console.print("[yellow]LLM Agent Server stopped[/yellow]")
    
    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle a client connection"""
        buffer = b''
        
        try:
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                buffer += data
                
                # Try to parse messages
                while len(buffer) >= 10:
                    try:
                        # Check if we have enough data
                        _, _, _, length = struct.unpack('!4sBBL', buffer[:10])
                        total_length = 10 + length
                        
                        if len(buffer) < total_length:
                            break  # Wait for more data
                        
                        msg_data = buffer[:total_length]
                        buffer = buffer[total_length:]
                        
                        msg_type, payload = BinaryProtocol.unpack_message(msg_data)
                        self._process_message(client_socket, msg_type, payload)
                    
                    except ValueError as e:
                        self.console.print(f"[red]Protocol error: {e}[/red]")
                        break
        
        except Exception as e:
            self.console.print(f"[red]Client {address} error: {e}[/red]")
        finally:
            client_socket.close()
            self.console.print(f"[dim]Client {address} disconnected[/dim]")
    
    def _process_message(self, client_socket: socket.socket, msg_type: int, payload: bytes):
        """Process incoming message"""
        try:
            if msg_type == BinaryProtocol.MSG_COMMAND:
                self._handle_command(client_socket, payload)
            
            elif msg_type == BinaryProtocol.MSG_CODE_GENERATE:
                self._handle_code_generate(client_socket, payload)
            
            elif msg_type == BinaryProtocol.MSG_EXECUTE:
                self._handle_execute(client_socket, payload)
            
            elif msg_type == BinaryProtocol.MSG_HEARTBEAT:
                self._handle_heartbeat(client_socket)
            
            else:
                self._send_error(client_socket, f"Unknown message type: {msg_type}")
        
        except Exception as e:
            self._send_error(client_socket, str(e))
    
    def _handle_command(self, client_socket: socket.socket, payload: bytes):
        """Handle command execution request"""
        try:
            data = BinaryProtocol.decode_json(payload)
            command = data.get('command', '')
            language = data.get('language', 'powershell')
            
            self.console.print(f"[yellow]Executing command: {command[:50]}...[/yellow]")
            
            # Execute command
            if language == 'powershell':
                exit_code, stdout, stderr = execute_powershell(
                    command,
                    lab_use=self.session_data.get('LAB_USE', 0)
                )
            else:
                exit_code, stdout, stderr = execute_cmd(
                    command,
                    lab_use=self.session_data.get('LAB_USE', 0)
                )
            
            # Send response
            response = {
                'exit_code': exit_code,
                'stdout': stdout,
                'stderr': stderr,
                'success': exit_code == 0
            }
            
            self._send_response(client_socket, response)
        
        except Exception as e:
            self._send_error(client_socket, str(e))
    
    def _handle_code_generate(self, client_socket: socket.socket, payload: bytes):
        """Handle code generation request"""
        try:
            spec = BinaryProtocol.decode_json(payload)
            
            self.console.print(f"[yellow]Generating {spec.get('language', 'code')} code...[/yellow]")
            
            code, file_path = self.code_generator.generate_code(spec)
            
            response = {
                'code': code,
                'file_path': file_path,
                'language': spec.get('language', 'python'),
                'success': True
            }
            
            self._send_response(client_socket, response)
        
        except Exception as e:
            self._send_error(client_socket, str(e))
    
    def _handle_execute(self, client_socket: socket.socket, payload: bytes):
        """Handle code execution request"""
        try:
            data = BinaryProtocol.decode_json(payload)
            file_path = data.get('file_path', '')
            language = data.get('language', 'python')
            args = data.get('args', [])
            
            self.console.print(f"[yellow]Executing {language} code: {file_path}[/yellow]")
            
            exit_code, stdout, stderr = self.code_generator.execute_code(file_path, language, args)
            
            response = {
                'exit_code': exit_code,
                'stdout': stdout,
                'stderr': stderr,
                'success': exit_code == 0
            }
            
            self._send_response(client_socket, response)
        
        except Exception as e:
            self._send_error(client_socket, str(e))
    
    def _handle_heartbeat(self, client_socket: socket.socket):
        """Handle heartbeat message"""
        response = {'status': 'alive', 'timestamp': str(os.times())}
        self._send_response(client_socket, response)
    
    def _send_response(self, client_socket: socket.socket, data: Dict[str, Any]):
        """Send response message"""
        payload = BinaryProtocol.encode_json(data)
        message = BinaryProtocol.pack_message(BinaryProtocol.MSG_RESPONSE, payload)
        client_socket.sendall(message)
    
    def _send_error(self, client_socket: socket.socket, error_msg: str):
        """Send error message"""
        payload = BinaryProtocol.encode_json({'error': error_msg})
        message = BinaryProtocol.pack_message(BinaryProtocol.MSG_ERROR, payload)
        client_socket.sendall(message)


class LLMAgentModule:
    """LLM Agent Module for TUI"""
    
    def __init__(self):
        self.server = None
        self.server_thread = None
    
    def run(self, console: Console, session_data: dict):
        """Run LLM agent module"""
        while True:
            console.print(Panel(
                "[bold]LLM Remote Agent[/bold]\n\n"
                "Self-coding execution system with binary protocol communication.",
                title="Module 7",
                border_style="cyan"
            ))
            console.print()
            
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_column("Option", style="cyan", width=3)
            table.add_column("Function", style="white")
            
            table.add_row("1", "Start LLM Agent Server")
            table.add_row("2", "Stop LLM Agent Server")
            table.add_row("3", "Server Status")
            table.add_row("4", "Test Code Generation")
            table.add_row("5", "Protocol Documentation")
            table.add_row("0", "Return to main menu")
            
            console.print(table)
            console.print()
            
            choice = Prompt.ask("Select function", choices=['0', '1', '2', '3', '4', '5'], default='0')
            
            if choice == '0':
                if self.server and self.server.running:
                    if Confirm.ask("[bold yellow]Stop server before exiting?[/bold yellow]", default=True):
                        self.server.stop()
                break
            
            elif choice == '1':
                self._start_server(console, session_data)
            
            elif choice == '2':
                self._stop_server(console)
            
            elif choice == '3':
                self._server_status(console)
            
            elif choice == '4':
                self._test_code_generation(console, session_data)
            
            elif choice == '5':
                self._protocol_documentation(console)
            
            console.print()
    
    def _start_server(self, console: Console, session_data: dict):
        """Start the LLM agent server"""
        if self.server and self.server.running:
            console.print("[yellow]Server is already running[/yellow]")
            return
        
        host = Prompt.ask("Server host", default="localhost")
        port = int(Prompt.ask("Server port", default="8888"))
        
        self.server = LLMAgentServer(console, session_data, host, port)
        
        self.server_thread = threading.Thread(target=self.server.start, daemon=True)
        self.server_thread.start()
        
        console.print(f"\n[green]Server starting on {host}:{port}...[/green]")
        console.print("[dim]Press Ctrl+C in server thread to stop[/dim]")
    
    def _stop_server(self, console: Console):
        """Stop the LLM agent server"""
        if not self.server or not self.server.running:
            console.print("[yellow]Server is not running[/yellow]")
            return
        
        self.server.stop()
        console.print("[green]Server stopped[/green]")
    
    def _server_status(self, console: Console):
        """Show server status"""
        if not self.server:
            console.print("[dim]Server not initialized[/dim]")
            return
        
        status = "Running" if self.server.running else "Stopped"
        console.print(f"\n[bold]Server Status:[/bold] {status}")
        
        if self.server.running:
            console.print(f"Host: {self.server.host}")
            console.print(f"Port: {self.server.port}")
            console.print(f"Active connections: {len(self.server.client_connections)}")
    
    def _test_code_generation(self, console: Console, session_data: dict):
        """Test code generation locally"""
        console.print("\n[bold cyan]Test Code Generation[/bold cyan]\n")
        
        language = Prompt.ask("Language", choices=['python', 'powershell', 'batch'], default='python')
        description = Prompt.ask("Code description", default="Print hello world")
        
        generator = CodeGenerator(console, session_data)
        
        spec = {
            'language': language,
            'description': description,
            'requirements': ['Print message', 'Return success'],
            'imports': []
        }
        
        try:
            code, file_path = generator.generate_code(spec)
            
            console.print(f"\n[green]Generated code:[/green]\n")
            console.print(f"[dim]{file_path}[/dim]\n")
            console.print(Panel(code, title="Generated Code", border_style="green"))
            
            if Confirm.ask("\n[bold]Execute generated code?[/bold]", default=False):
                exit_code, stdout, stderr = generator.execute_code(file_path, language)
                
                console.print(f"\n[bold]Execution Result:[/bold]")
                console.print(f"Exit Code: {exit_code}")
                if stdout:
                    console.print(f"Output:\n{stdout}")
                if stderr:
                    console.print(f"Error:\n{stderr}")
        
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        finally:
            generator.cleanup()
    
    def _protocol_documentation(self, console: Console):
        """Show protocol documentation"""
        console.print("\n[bold cyan]Binary Protocol Documentation[/bold cyan]\n")
        
        doc = """
[bold]Protocol Format:[/bold]
  MAGIC (4 bytes): 0xAABBCCDD
  VERSION (1 byte): Protocol version (currently 1)
  TYPE (1 byte): Message type
  LENGTH (4 bytes): Payload length (big-endian)
  PAYLOAD (N bytes): Message data (JSON encoded)

[bold]Message Types:[/bold]
  0x01 - MSG_COMMAND: Execute a command
  0x02 - MSG_CODE_GENERATE: Generate code from specification
  0x03 - MSG_EXECUTE: Execute generated code
  0x04 - MSG_RESPONSE: Response message
  0x05 - MSG_ERROR: Error message
  0x06 - MSG_HEARTBEAT: Keep-alive message

[bold]MSG_COMMAND Payload (JSON):[/bold]
  {
    "command": "string",
    "language": "powershell|batch"
  }

[bold]MSG_CODE_GENERATE Payload (JSON):[/bold]
  {
    "language": "python|powershell|batch",
    "description": "string",
    "requirements": ["string"],
    "imports": ["string"]
  }

[bold]MSG_EXECUTE Payload (JSON):[/bold]
  {
    "file_path": "string",
    "language": "python|powershell|batch",
    "args": ["string"]
  }

[bold]Response Payload (JSON):[/bold]
  {
    "exit_code": int,
    "stdout": "string",
    "stderr": "string",
    "success": bool
  }
        """
        
        console.print(doc)
