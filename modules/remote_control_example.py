"""
Example: Using Remote Control Hub Hooks for Programming

This demonstrates how to easily program remote control behavior using hooks.
"""

import asyncio
from modules.llm_agent import LLMAgentServer
from modules.remote_hub import (
    RemoteControlHub, RemoteEvent, EventType, HookPriority,
    RemoteControlPlugin, hook_handler
)
from rich.console import Console


# Example 1: Simple hook registration
async def example_simple_hooks():
    """Simple hook examples"""
    console = Console()
    session_data = {}
    
    # Create server with hub
    server = LLMAgentServer(console, session_data, host='localhost', port=8888)
    hub = server.get_hub()
    
    # Hook 1: Log all commands
    async def log_commands(event: RemoteEvent, context: dict):
        if event.event_type == EventType.COMMAND_RECEIVED:
            console.print(f"[yellow]Command: {event.data.get('command_type')}[/yellow]")
        return event
    
    hub.register_hook("log_commands", log_commands, [EventType.COMMAND_RECEIVED])
    
    # Hook 2: Block dangerous commands
    async def block_dangerous(event: RemoteEvent, context: dict):
        if event.event_type == EventType.COMMAND_RECEIVED:
            cmd_type = event.data.get('command_type')
            dangerous = [0x3003]  # SELF_CODE_APPLY_PATCH
            
            if cmd_type in dangerous:
                console.print(f"[red]Blocked dangerous command: {cmd_type}[/red]")
                await hub.emit_event(
                    EventType.ERROR_OCCURRED,
                    "security_hook",
                    {'error': 'Dangerous command blocked'}
                )
                return None  # Block the event
        return event
    
    hub.register_hook(
        "block_dangerous",
        block_dangerous,
        [EventType.COMMAND_RECEIVED],
        priority=HookPriority.HIGH
    )
    
    # Hook 3: Transform commands
    async def transform_command(event: RemoteEvent, context: dict):
        if event.event_type == EventType.COMMAND_RECEIVED:
            # Modify command data
            event.data['transformed'] = True
            event.data['original_command'] = event.data.get('command_type')
        return event
    
    hub.register_hook("transform", transform_command, [EventType.COMMAND_RECEIVED])
    
    return server


# Example 2: Using decorator syntax
@hook_handler([EventType.COMMAND_RECEIVED], HookPriority.NORMAL)
async def my_command_handler(event: RemoteEvent, context: dict):
    """Handle commands with decorator"""
    print(f"Handling command: {event.data.get('command_type')}")
    return event


# Example 3: Custom plugin
class CustomSecurityPlugin(RemoteControlPlugin):
    """Custom security plugin"""
    
    def __init__(self):
        super().__init__("custom_security")
        self.blocked_ips = set()
    
    def get_hooks(self):
        async def check_ip(event: RemoteEvent, context: dict):
            if event.event_type == EventType.CONNECTION_ESTABLISHED:
                address = event.data.get('address', '')
                ip = address.split(':')[0] if ':' in address else address
                
                if ip in self.blocked_ips:
                    return None  # Block connection
            return event
        
        return {
            'check_ip': {
                'handler': check_ip,
                'event_types': [EventType.CONNECTION_ESTABLISHED],
                'priority': HookPriority.CRITICAL,
                'metadata': {'description': 'Block connections from blocked IPs'}
            }
        }
    
    def block_ip(self, ip: str):
        """Block an IP address"""
        self.blocked_ips.add(ip)
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        self.blocked_ips.discard(ip)


# Example 4: Command transformation plugin
class CommandTransformerPlugin(RemoteControlPlugin):
    """Transform commands before execution"""
    
    def __init__(self):
        super().__init__("command_transformer")
        self.transformations = {}
    
    def get_hooks(self):
        async def transform(event: RemoteEvent, context: dict):
            if event.event_type == EventType.COMMAND_RECEIVED:
                cmd_type = event.data.get('command_type')
                
                # Apply transformation if exists
                if cmd_type in self.transformations:
                    new_cmd = self.transformations[cmd_type]
                    event.data['command_type'] = new_cmd
                    event.data['transformed'] = True
            
            return event
        
        return {
            'transform': {
                'handler': transform,
                'event_types': [EventType.COMMAND_RECEIVED],
                'priority': HookPriority.HIGH,
                'metadata': {'description': 'Transform commands'}
            }
        }
    
    def add_transformation(self, from_cmd: int, to_cmd: int):
        """Add a command transformation"""
        self.transformations[from_cmd] = to_cmd


# Example 5: Complete usage
async def example_complete_usage():
    """Complete example showing all features"""
    console = Console()
    session_data = {}
    
    # Create server
    server = LLMAgentServer(console, session_data)
    hub = server.get_hub()
    
    # Register custom plugins
    security_plugin = CustomSecurityPlugin()
    security_plugin.block_ip("192.168.1.100")
    hub.register_plugin(security_plugin)
    
    transformer_plugin = CommandTransformerPlugin()
    transformer_plugin.add_transformation(0x3001, 0x3002)  # Transform plan request
    hub.register_plugin(transformer_plugin)
    
    # Register individual hooks
    async def monitor_all(event: RemoteEvent, context: dict):
        """Monitor all events"""
        console.print(f"[dim]Event: {event.event_type.value}[/dim]")
        return event
    
    hub.register_hook("monitor", monitor_all, priority=HookPriority.MONITOR)
    
    # Register decorator-based hook
    hub.register_hook(
        "decorator_hook",
        my_command_handler,
        my_command_handler._hook_event_types,
        my_command_handler._hook_priority
    )
    
    # Start server
    server.start()
    
    return server


# Example 6: Event history and analysis
async def example_event_analysis():
    """Analyze event history"""
    console = Console()
    session_data = {}
    
    server = LLMAgentServer(console, session_data)
    hub = server.get_hub()
    
    # After some events occur...
    
    # Get all events
    all_events = hub.get_event_history()
    console.print(f"Total events: {len(all_events)}")
    
    # Get command events only
    command_events = hub.get_event_history(EventType.COMMAND_RECEIVED)
    console.print(f"Command events: {len(command_events)}")
    
    # Analyze events
    event_counts = {}
    for event in all_events:
        event_counts[event.event_type] = event_counts.get(event.event_type, 0) + 1
    
    console.print("Event counts:")
    for event_type, count in event_counts.items():
        console.print(f"  {event_type.value}: {count}")


if __name__ == "__main__":
    # Run examples
    asyncio.run(example_complete_usage())
