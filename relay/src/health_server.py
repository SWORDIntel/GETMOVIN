#!/usr/bin/env python3
"""
Health Check Server for AI Relay

Provides health-check and metrics endpoints:
- /healthz - Basic health check
- /readyz - Readiness check
- /metrics - Prometheus metrics
"""

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

# Check for aiohttp availability
try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from relay_daemon import RelayDaemon


class HealthServer:
    """Health check HTTP server"""
    
    def __init__(self, relay_daemon: Optional[RelayDaemon], port: int = 9090):
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp library not available. Install with: pip install aiohttp")
        
        self.relay_daemon = relay_daemon
        self.port = port
        self.app = web.Application()
        self.setup_routes()
    
    def setup_routes(self):
        """Setup HTTP routes"""
        self.app.router.add_get('/healthz', self.health_check)
        self.app.router.add_get('/readyz', self.readiness_check)
        self.app.router.add_get('/metrics', self.metrics)
        self.app.router.add_get('/stats', self.stats)
    
    async def health_check(self, request):
        """Basic health check"""
        return web.json_response({
            'status': 'healthy',
            'timestamp': asyncio.get_event_loop().time()
        })
    
    async def readiness_check(self, request):
        """Readiness check"""
        # Check if relay can accept new connections
        max_sessions = self.relay_daemon.config.get('limits.max_sessions', 100)
        active_sessions = len(self.relay_daemon.sessions)
        
        ready = active_sessions < max_sessions
        
        return web.json_response({
            'status': 'ready' if ready else 'not_ready',
            'active_sessions': active_sessions,
            'max_sessions': max_sessions
        }, status=200 if ready else 503)
    
    async def metrics(self, request):
        """Prometheus metrics"""
        stats = self.relay_daemon.get_stats()
        
        metrics = []
        metrics.append(f"# HELP ai_relay_active_sessions Number of active relay sessions")
        metrics.append(f"# TYPE ai_relay_active_sessions gauge")
        metrics.append(f"ai_relay_active_sessions {stats['active_sessions']}")
        
        # Session metrics
        for session in stats['sessions']:
            session_id = session['session_id']
            metrics.append(f"# HELP ai_relay_session_bytes_sent Bytes sent in session")
            metrics.append(f"# TYPE ai_relay_session_bytes_sent counter")
            metrics.append(f'ai_relay_session_bytes_sent{{session="{session_id}"}} {session["bytes_sent"]}')
            
            metrics.append(f"# HELP ai_relay_session_bytes_received Bytes received in session")
            metrics.append(f"# TYPE ai_relay_session_bytes_received counter")
            metrics.append(f'ai_relay_session_bytes_received{{session="{session_id}"}} {session["bytes_received"]}')
        
        return web.Response(text='\n'.join(metrics), content_type='text/plain')
    
    async def stats(self, request):
        """Detailed statistics"""
        stats = self.relay_daemon.get_stats()
        return web.json_response(stats)
    
    async def start(self):
        """Start health server"""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.port)
        await site.start()
        logging.info(f"Health server started on port {self.port}")


async def main():
    """Main entry point for health server"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AI Relay Health Server')
    parser.add_argument('--port', type=int, default=9090, help='Health server port')
    parser.add_argument('--relay-config', default='/etc/ai-relay/relay.yaml',
                       help='Path to relay configuration')
    
    args = parser.parse_args()
    
    # Create relay daemon instance (for stats)
    relay_daemon = RelayDaemon(args.relay_config)
    
    # Start health server
    health_server = HealthServer(relay_daemon, args.port)
    await health_server.start()
    
    # Keep running
    await asyncio.Future()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Health server stopped")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
