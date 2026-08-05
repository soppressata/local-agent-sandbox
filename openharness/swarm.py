"""
Swarm module for OpenHarness.
Provides core functionality for the swarm subsystem.
"""
import asyncio
import socket
import json
import logging
from typing import Set, Optional

logger = logging.getLogger(__name__)

class P2PDiscovery:
    """
    Handles peer-to-peer discovery of other OpenHarness sandbox instances 
    on the local network using UDP broadcast.
    """
    def __init__(self, port: int = 54321, broadcast_interval: int = 5):
        self.port = port
        self.broadcast_interval = broadcast_interval
        self.peers: Set[str] = set()
        self._running = False
        self.transport: Optional[asyncio.DatagramTransport] = None

    class DiscoveryProtocol(asyncio.DatagramProtocol):
        def __init__(self, parent: 'P2PDiscovery'):
            self.parent = parent

        def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
            try:
                message = json.loads(data.decode('utf-8'))
                if message.get('type') == 'openharness_discovery':
                    peer_ip = addr[0]
                    # Don't add ourselves if we receive our own broadcast
                    local_ip = socket.gethostbyname(socket.gethostname())
                    if peer_ip != local_ip and peer_ip not in self.parent.peers:
                        logger.info(f"Discovered new OpenHarness peer: {peer_ip}")
                        self.parent.peers.add(peer_ip)
            except json.JSONDecodeError:
                pass

    async def start(self) -> None:
        """Starts the P2P discovery service."""
        self._running = True
        loop = asyncio.get_running_loop()
        
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self.DiscoveryProtocol(self),
            local_addr=('0.0.0.0', self.port),
            allow_broadcast=True
        )
        
        asyncio.create_task(self._broadcast_loop())
        logger.info(f"P2P Discovery started on port {self.port}")

    async def _broadcast_loop(self) -> None:
        """Continuously broadcasts presence to the local network."""
        message = json.dumps({'type': 'openharness_discovery'}).encode('utf-8')
        while self._running and self.transport:
            try:
                self.transport.sendto(message, ('255.255.255.255', self.port))
            except Exception as e:
                logger.debug(f"Broadcast failed: {e}")
            await asyncio.sleep(self.broadcast_interval)

    async def stop(self) -> None:
        """Stops the P2P discovery service."""
        self._running = False
        if self.transport:
            self.transport.close()
        logger.info("P2P Discovery stopped")
        
    def get_peers(self) -> Set[str]:
        """Returns the set of discovered peers."""
        return self.peers.copy()
