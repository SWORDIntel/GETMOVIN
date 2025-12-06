# Remote Control Hub - Programming Guide

## Overview

The Remote Control Hub provides an easy-to-use hook system for programming remote control behavior in the LLM Agent module. It enables event-driven architecture with hooks, plugins, and easy extensibility.

## Key Features

- **Event-Driven Architecture**: All remote control events are emitted through the hub
- **Hook System**: Register hooks to intercept, modify, or block events
- **Plugin Support**: Create reusable plugins for common functionality
- **Priority System**: Control hook execution order
- **Event History**: Track all events for analysis
- **Easy API**: Simple, intuitive interface for programming

## Quick Start

### Basic Hook Registration

```python
from modules.llm_agent import LLMAgentServer
from modules.remote_hub import EventType, HookPriority
from rich.console import Console

# Create server
console = Console()
server = LLMAgentServer(console, {}, host='localhost', port=8888)
hub = server.get_hub()

# Register a hook
async def my_hook(event, context):
    if event.event_type == EventType.COMMAND_RECEIVED:
        print(f"Command received: {event.data.get('command_type')}")
    return event

hub.register_hook("my_hook", my_hook, [EventType.COMMAND_RECEIVED])

# Start server
server.start()
```

### Using Decorator Syntax

```python
from modules.remote_hub import hook_handler, EventType, HookPriority

@hook_handler([EventType.COMMAND_RECEIVED], HookPriority.HIGH)
async def handle_command(event, context):
    print(f"Handling command: {event.data.get('command_type')}")
    return event

# Register the decorated handler
hub.register_hook("decorated_hook", handle_command, 
                  handle_command._hook_event_types,
                  handle_command._hook_priority)
```

## Event Types

Available event types:

- `CONNECTION_ESTABLISHED` - New connection established
- `CONNECTION_LOST` - Connection lost
- `COMMAND_RECEIVED` - Command received from remote
- `COMMAND_EXECUTED` - Command executed successfully
- `CODE_GENERATED` - Code generation completed
- `CODE_EXECUTED` - Code execution completed
- `ERROR_OCCURRED` - Error occurred
- `HEARTBEAT` - Heartbeat received
- `REGISTRATION` - App registration
- `TELEMETRY` - Telemetry data
- `CUSTOM` - Custom events

## Hook System

### Hook Priorities

Hooks execute in priority order:

- `CRITICAL` (0) - Execute first (e.g., security checks)
- `HIGH` (1) - High priority (e.g., filtering)
- `NORMAL` (2) - Normal priority (default)
- `LOW` (3) - Low priority (e.g., logging)
- `MONITOR` (4) - Monitoring only (no modifications)

### Hook Handler Signature

```python
async def hook_handler(event: RemoteEvent, context: Dict[str, Any]) -> Optional[RemoteEvent]:
    """
    Args:
        event: The event being processed
        context: Additional context including:
            - 'hub': Reference to RemoteControlHub
            - Any custom context passed to emit_event()
    
    Returns:
        Modified event, None to block event, or original event
    """
    # Modify event
    event.data['modified'] = True
    return event
    
    # Or block event
    # return None
```

### Blocking Events

Return `None` from a hook to block the event:

```python
async def block_dangerous(event, context):
    if event.data.get('command_type') == 0x3003:  # Dangerous command
        return None  # Block the event
    return event
```

### Modifying Events

Return a modified event:

```python
async def transform_command(event, context):
    if event.event_type == EventType.COMMAND_RECEIVED:
        event.data['transformed'] = True
        event.data['original'] = event.data.get('command_type')
        event.data['command_type'] = 0x3002  # Transform to safe command
    return event
```

## Plugin System

### Creating a Plugin

```python
from modules.remote_hub import RemoteControlPlugin, EventType, HookPriority

class MyPlugin(RemoteControlPlugin):
    def __init__(self):
        super().__init__("my_plugin")
        self.config = {}
    
    def get_hooks(self):
        async def my_handler(event, context):
            # Handle event
            return event
        
        return {
            'my_hook': {
                'handler': my_handler,
                'event_types': [EventType.COMMAND_RECEIVED],
                'priority': HookPriority.NORMAL,
                'metadata': {'description': 'My custom hook'}
            }
        }
    
    async def initialize(self):
        """Called when plugin is registered"""
        pass
    
    async def cleanup(self):
        """Called when plugin is unregistered"""
        pass
```

### Registering a Plugin

```python
plugin = MyPlugin()
hub.register_plugin(plugin)
```

### Built-in Plugins

#### LoggingPlugin

Logs all events:

```python
from modules.remote_hub import LoggingPlugin

hub.register_plugin(LoggingPlugin(log_level=logging.INFO))
```

#### CommandFilterPlugin

Filters commands based on allow/block lists:

```python
from modules.remote_hub import CommandFilterPlugin

plugin = CommandFilterPlugin(
    allowed_commands=[0x3001, 0x3002],  # Only allow these commands
    blocked_commands=[0x3003]  # Block these commands
)
hub.register_plugin(plugin)
```

#### RateLimitPlugin

Rate limits events:

```python
from modules.remote_hub import RateLimitPlugin

plugin = RateLimitPlugin(max_events_per_second=10.0)
hub.register_plugin(plugin)
```

## Advanced Usage

### Emitting Custom Events

```python
await hub.emit_event(
    EventType.CUSTOM,
    "my_source",
    {'custom_data': 'value'},
    context={'additional': 'context'}
)
```

### Event History

```python
# Get all events
all_events = hub.get_event_history()

# Get specific event type
command_events = hub.get_event_history(EventType.COMMAND_RECEIVED, limit=100)

# Clear history
hub.clear_history()
```

### Managing Hooks

```python
# Enable/disable hooks
hub.enable_hook("my_hook")
hub.disable_hook("my_hook")

# Unregister hook
hub.unregister_hook("my_hook")

# Get all hooks
all_hooks = hub.get_hooks()
```

### Managing Plugins

```python
# Unregister plugin
hub.unregister_plugin("my_plugin")

# Get all plugins
all_plugins = hub.get_plugins()
```

## Example: Security Plugin

```python
class SecurityPlugin(RemoteControlPlugin):
    def __init__(self):
        super().__init__("security")
        self.blocked_ips = set()
        self.allowed_commands = {0x3001, 0x3002}
    
    def get_hooks(self):
        async def check_ip(event, context):
            if event.event_type == EventType.CONNECTION_ESTABLISHED:
                address = event.data.get('address', '')
                ip = address.split(':')[0] if ':' in address else address
                if ip in self.blocked_ips:
                    return None  # Block connection
            return event
        
        async def check_command(event, context):
            if event.event_type == EventType.COMMAND_RECEIVED:
                cmd_type = event.data.get('command_type')
                if cmd_type not in self.allowed_commands:
                    await context['hub'].emit_event(
                        EventType.ERROR_OCCURRED,
                        "security",
                        {'error': f'Command {cmd_type} not allowed'}
                    )
                    return None  # Block command
            return event
        
        return {
            'check_ip': {
                'handler': check_ip,
                'event_types': [EventType.CONNECTION_ESTABLISHED],
                'priority': HookPriority.CRITICAL
            },
            'check_command': {
                'handler': check_command,
                'event_types': [EventType.COMMAND_RECEIVED],
                'priority': HookPriority.CRITICAL
            }
        }
    
    def block_ip(self, ip: str):
        self.blocked_ips.add(ip)
    
    def allow_command(self, cmd_type: int):
        self.allowed_commands.add(cmd_type)
```

## Integration with LLM Agent Server

The hub is automatically created when you create an LLMAgentServer:

```python
server = LLMAgentServer(console, session_data)
hub = server.get_hub()  # Get the hub

# Register hooks
hub.register_hook("my_hook", my_handler)

# Or use convenience methods
server.register_hook("my_hook", my_handler)
server.register_plugin(my_plugin)
```

## Best Practices

1. **Use appropriate priorities**: Critical hooks (security) should have CRITICAL priority
2. **Keep hooks simple**: Hooks should be fast and focused
3. **Handle errors**: Wrap hook logic in try/except blocks
4. **Use plugins**: Group related hooks into plugins for reusability
5. **Document hooks**: Add metadata to hooks for documentation
6. **Test hooks**: Test hooks independently before integration

## API Reference

See `modules/remote_hub.py` for complete API documentation.

## Examples

See `modules/remote_control_example.py` for complete examples.
