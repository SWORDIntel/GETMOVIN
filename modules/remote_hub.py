"""
Remote Control Hub - Central Interface for Programming Remote Control

Provides easy hooks and event handlers for remote control programming.
Supports plugin system for extensibility.
"""

import asyncio
import json
import logging
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Callable, Any, Set

# Protocol support - try typing first, fallback to typing_extensions
try:
    from typing import Protocol
except ImportError:
    try:
        from typing_extensions import Protocol
    except ImportError:
        # Fallback: simple Protocol base class
        class Protocol:
            """Simple Protocol base class for older Python versions"""
            pass


class HookPriority(Enum):
    """Hook execution priority"""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    MONITOR = 4


class EventType(Enum):
    """Remote control event types"""
    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_LOST = "connection_lost"
    COMMAND_RECEIVED = "command_received"
    COMMAND_EXECUTED = "command_executed"
    CODE_GENERATED = "code_generated"
    CODE_EXECUTED = "code_executed"
    ERROR_OCCURRED = "error_occurred"
    HEARTBEAT = "heartbeat"
    REGISTRATION = "registration"
    TELEMETRY = "telemetry"
    CUSTOM = "custom"


@dataclass
class RemoteEvent:
    """Remote control event"""
    event_type: EventType
    timestamp: float
    source: str
    data: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))


class HookHandler(Protocol):
    """Protocol for hook handlers"""
    
    async def __call__(self, event: RemoteEvent, context: Dict[str, Any]) -> Optional[RemoteEvent]:
        """Handle hook event"""
        ...


@dataclass
class Hook:
    """Hook registration"""
    name: str
    handler: HookHandler
    priority: HookPriority = HookPriority.NORMAL
    event_types: Set[EventType] = field(default_factory=set)
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class RemoteControlHub:
    """
    Central hub for remote control programming
    
    Provides:
    - Event-driven architecture
    - Hook system for custom programming
    - Plugin support
    - Easy API for remote control
    """
    
    def __init__(self, name: str = "default_hub"):
        self.name = name
        self.hooks: Dict[str, Hook] = {}
        self.hooks_by_event: Dict[EventType, List[Hook]] = defaultdict(list)
        self.plugins: Dict[str, 'RemoteControlPlugin'] = {}
        self.event_history: List[RemoteEvent] = []
        self.max_history = 1000
        self.logger = logging.getLogger(f"RemoteHub.{name}")
        self._lock = asyncio.Lock()
        
    def register_hook(
        self,
        name: str,
        handler: HookHandler,
        event_types: Optional[List[EventType]] = None,
        priority: HookPriority = HookPriority.NORMAL,
        enabled: bool = True,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Register a hook for remote control events
        
        Args:
            name: Unique hook name
            handler: Async handler function (event, context) -> Optional[event]
            event_types: List of event types to hook (None = all events)
            priority: Hook priority (higher priority executes first)
            enabled: Whether hook is enabled
            metadata: Optional metadata for the hook
            
        Returns:
            Hook ID
            
        Example:
            async def my_handler(event, context):
                if event.event_type == EventType.COMMAND_RECEIVED:
                    print(f"Command: {event.data.get('command')}")
                return event
            
            hub.register_hook("my_hook", my_handler, [EventType.COMMAND_RECEIVED])
        """
        if name in self.hooks:
            raise ValueError(f"Hook '{name}' already registered")
        
        hook = Hook(
            name=name,
            handler=handler,
            priority=priority,
            event_types=set(event_types) if event_types else set(),
            enabled=enabled,
            metadata=metadata or {}
        )
        
        self.hooks[name] = hook
        
        # Index by event type
        if event_types:
            for event_type in event_types:
                self.hooks_by_event[event_type].append(hook)
        else:
            # Hook all events
            for event_type in EventType:
                self.hooks_by_event[event_type].append(hook)
        
        # Sort hooks by priority
        for event_type in self.hooks_by_event:
            self.hooks_by_event[event_type].sort(key=lambda h: h.priority.value)
        
        self.logger.info(f"Registered hook: {name} (priority={priority.name}, events={len(hook.event_types)})")
        return name
    
    def unregister_hook(self, name: str) -> bool:
        """Unregister a hook"""
        if name not in self.hooks:
            return False
        
        hook = self.hooks[name]
        
        # Remove from event index
        for event_type in list(self.hooks_by_event.keys()):
            if hook in self.hooks_by_event[event_type]:
                self.hooks_by_event[event_type].remove(hook)
        
        del self.hooks[name]
        self.logger.info(f"Unregistered hook: {name}")
        return True
    
    def enable_hook(self, name: str) -> bool:
        """Enable a hook"""
        if name not in self.hooks:
            return False
        self.hooks[name].enabled = True
        return True
    
    def disable_hook(self, name: str) -> bool:
        """Disable a hook"""
        if name not in self.hooks:
            return False
        self.hooks[name].enabled = False
        return True
    
    async def emit_event(
        self,
        event_type: EventType,
        source: str,
        data: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> RemoteEvent:
        """
        Emit an event and trigger hooks
        
        Args:
            event_type: Type of event
            source: Source identifier
            data: Event data
            context: Additional context for hooks
            
        Returns:
            The emitted event (may be modified by hooks)
        """
        import time
        
        event = RemoteEvent(
            event_type=event_type,
            timestamp=time.time(),
            source=source,
            data=data or {}
        )
        
        async with self._lock:
            # Get relevant hooks
            hooks = self.hooks_by_event.get(event_type, [])
            
            # Also include hooks that listen to all events
            all_event_hooks = [
                h for h in self.hooks.values()
                if not h.event_types and h.enabled
            ]
            
            all_hooks = sorted(
                hooks + all_event_hooks,
                key=lambda h: h.priority.value
            )
            
            # Execute hooks
            current_event = event
            hook_context = context or {}
            hook_context['hub'] = self
            
            for hook in all_hooks:
                if not hook.enabled:
                    continue
                
                try:
                    result = await hook.handler(current_event, hook_context)
                    if result is not None:
                        current_event = result
                except Exception as e:
                    self.logger.error(f"Hook '{hook.name}' error: {e}", exc_info=True)
            
            # Store in history
            self.event_history.append(current_event)
            if len(self.event_history) > self.max_history:
                self.event_history.pop(0)
            
            return current_event
    
    def register_plugin(self, plugin: 'RemoteControlPlugin') -> bool:
        """Register a plugin"""
        if plugin.name in self.plugins:
            self.logger.warning(f"Plugin '{plugin.name}' already registered")
            return False
        
        plugin.hub = self
        self.plugins[plugin.name] = plugin
        
        # Register plugin hooks
        for hook_name, hook_info in plugin.get_hooks().items():
            full_name = f"{plugin.name}.{hook_name}"
            self.register_hook(
                name=full_name,
                handler=hook_info['handler'],
                event_types=hook_info.get('event_types'),
                priority=hook_info.get('priority', HookPriority.NORMAL),
                metadata={'plugin': plugin.name, **hook_info.get('metadata', {})}
            )
        
        self.logger.info(f"Registered plugin: {plugin.name}")
        return True
    
    def unregister_plugin(self, name: str) -> bool:
        """Unregister a plugin"""
        if name not in self.plugins:
            return False
        
        plugin = self.plugins[name]
        
        # Unregister plugin hooks
        for hook_name in plugin.get_hooks().keys():
            full_name = f"{plugin.name}.{hook_name}"
            self.unregister_hook(full_name)
        
        plugin.hub = None
        del self.plugins[name]
        self.logger.info(f"Unregistered plugin: {name}")
        return True
    
    def get_hooks(self) -> Dict[str, Hook]:
        """Get all registered hooks"""
        return self.hooks.copy()
    
    def get_plugins(self) -> Dict[str, 'RemoteControlPlugin']:
        """Get all registered plugins"""
        return self.plugins.copy()
    
    def get_event_history(self, event_type: Optional[EventType] = None, limit: int = 100) -> List[RemoteEvent]:
        """Get event history"""
        events = self.event_history
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]
    
    def clear_history(self):
        """Clear event history"""
        self.event_history.clear()


class RemoteControlPlugin(ABC):
    """Base class for remote control plugins"""
    
    def __init__(self, name: str):
        self.name = name
        self.hub: Optional[RemoteControlHub] = None
        self.enabled = True
    
    @abstractmethod
    def get_hooks(self) -> Dict[str, Dict[str, Any]]:
        """
        Return hooks provided by this plugin
        
        Returns:
            Dict mapping hook names to hook configuration:
            {
                'hook_name': {
                    'handler': async function,
                    'event_types': [EventType, ...],
                    'priority': HookPriority,
                    'metadata': {...}
                }
            }
        """
        pass
    
    async def initialize(self):
        """Called when plugin is registered"""
        pass
    
    async def cleanup(self):
        """Called when plugin is unregistered"""
        pass
    
    def enable(self):
        """Enable plugin"""
        self.enabled = True
    
    def disable(self):
        """Disable plugin"""
        self.enabled = False


# Convenience decorators for hook registration

def hook_handler(event_types: List[EventType], priority: HookPriority = HookPriority.NORMAL):
    """
    Decorator for hook handlers
    
    Example:
        @hook_handler([EventType.COMMAND_RECEIVED], HookPriority.HIGH)
        async def handle_command(event, context):
            print(f"Command: {event.data.get('command')}")
            return event
    """
    def decorator(func: HookHandler):
        func._hook_event_types = event_types
        func._hook_priority = priority
        return func
    return decorator


# Built-in plugins

class LoggingPlugin(RemoteControlPlugin):
    """Plugin for logging all events"""
    
    def __init__(self, log_level: int = logging.INFO):
        super().__init__("logging")
        self.log_level = log_level
    
    def get_hooks(self) -> Dict[str, Dict[str, Any]]:
        async def log_event(event: RemoteEvent, context: Dict[str, Any]) -> Optional[RemoteEvent]:
            if not self.enabled:
                return event
            
            logger = logging.getLogger(f"RemoteHub.{self.name}")
            logger.log(
                self.log_level,
                f"Event: {event.event_type.value} from {event.source} - {event.data}"
            )
            return event
        
        return {
            'log_all': {
                'handler': log_event,
                'event_types': None,  # All events
                'priority': HookPriority.MONITOR,
                'metadata': {'description': 'Log all events'}
            }
        }


class CommandFilterPlugin(RemoteControlPlugin):
    """Plugin for filtering commands"""
    
    def __init__(self, allowed_commands: Optional[List[str]] = None, blocked_commands: Optional[List[str]] = None):
        super().__init__("command_filter")
        self.allowed_commands = set(allowed_commands) if allowed_commands else None
        self.blocked_commands = set(blocked_commands) if blocked_commands else set()
    
    def get_hooks(self) -> Dict[str, Dict[str, Any]]:
        async def filter_command(event: RemoteEvent, context: Dict[str, Any]) -> Optional[RemoteEvent]:
            if not self.enabled or event.event_type != EventType.COMMAND_RECEIVED:
                return event
            
            command = event.data.get('command', '')
            
            # Check blocked commands
            if command in self.blocked_commands:
                await context['hub'].emit_event(
                    EventType.ERROR_OCCURRED,
                    self.name,
                    {'error': f'Command blocked: {command}'}
                )
                return None  # Block event
            
            # Check allowed commands
            if self.allowed_commands and command not in self.allowed_commands:
                await context['hub'].emit_event(
                    EventType.ERROR_OCCURRED,
                    self.name,
                    {'error': f'Command not allowed: {command}'}
                )
                return None  # Block event
            
            return event
        
        return {
            'filter': {
                'handler': filter_command,
                'event_types': [EventType.COMMAND_RECEIVED],
                'priority': HookPriority.HIGH,
                'metadata': {'description': 'Filter commands'}
            }
        }


class RateLimitPlugin(RemoteControlPlugin):
    """Plugin for rate limiting events"""
    
    def __init__(self, max_events_per_second: float = 10.0):
        super().__init__("rate_limit")
        self.max_events_per_second = max_events_per_second
        self.event_times: List[float] = []
    
    def get_hooks(self) -> Dict[str, Dict[str, Any]]:
        async def rate_limit(event: RemoteEvent, context: Dict[str, Any]) -> Optional[RemoteEvent]:
            if not self.enabled:
                return event
            
            import time
            now = time.time()
            
            # Clean old events
            self.event_times = [t for t in self.event_times if now - t < 1.0]
            
            # Check rate limit
            if len(self.event_times) >= self.max_events_per_second:
                await context['hub'].emit_event(
                    EventType.ERROR_OCCURRED,
                    self.name,
                    {'error': 'Rate limit exceeded'}
                )
                return None  # Block event
            
            self.event_times.append(now)
            return event
        
        return {
            'rate_limit': {
                'handler': rate_limit,
                'event_types': None,  # All events
                'priority': HookPriority.CRITICAL,
                'metadata': {'description': 'Rate limit events'}
            }
        }
