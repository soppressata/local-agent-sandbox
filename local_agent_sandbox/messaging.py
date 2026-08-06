"""Thread-safe, strictly ordered in-process messaging for virtual agents."""

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import threading
import time
import uuid
from typing import Any, Deque, Dict, List, Optional


class MessageKind(str, Enum):
    """The delivery mode of a message."""

    DIRECT = "direct"
    BROADCAST = "broadcast"


@dataclass(frozen=True)
class Message:
    """An immutable message delivered to a virtual inbox."""

    sender: str
    recipient: str
    body: Any
    kind: MessageKind = MessageKind.DIRECT
    priority: int = 0
    message_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    sequence: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    @classmethod
    def direct(cls, sender: str, recipient: str, body: Any,
               metadata: Optional[Dict[str, Any]] = None) -> "Message":
        """Construct a direct message without delivering it."""
        return cls(sender, recipient, body, MessageKind.DIRECT, metadata=dict(metadata or {}))

    @classmethod
    def broadcast(cls, sender: str, body: Any,
                  metadata: Optional[Dict[str, Any]] = None) -> "Message":
        """Construct a broadcast message without delivering it."""
        return cls(sender, "*", body, MessageKind.BROADCAST, metadata=dict(metadata or {}))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the message to a JSON-compatible dictionary."""
        return {
            "message_id": self.message_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "body": self.body,
            "kind": self.kind.value,
            "priority": self.priority,
            "sequence": self.sequence,
            "metadata": dict(self.metadata),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Message":
        """Create a message from :meth:`to_dict` output."""
        return cls(
            message_id=str(data["message_id"]),
            sender=str(data["sender"]),
            recipient=str(data["recipient"]),
            body=data["body"],
            kind=MessageKind(data["kind"]),
            priority=int(data.get("priority", 0)),
            sequence=int(data.get("sequence", 0)),
            metadata=dict(data.get("metadata", {})),
            timestamp=float(data.get("timestamp", time.time())),
        )


class InboxNotFoundError(KeyError):
    """Raised when an operation addresses an unregistered inbox."""


class InboxOverflowError(RuntimeError):
    """Raised when a message would exceed an inbox capacity."""


class VirtualInbox:
    """A bounded FIFO inbox owned by one virtual agent."""

    def __init__(self, owner: str, capacity: int = 1000) -> None:
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self.owner = owner
        self.capacity = capacity
        self._messages: Deque[Message] = deque()
        self._read: Set[str] = set()
        self._lock = threading.RLock()

    @property
    def unread_count(self) -> int:
        """Return the number of messages not marked read or acknowledged."""
        with self._lock:
            return sum(message.message_id not in self._read for message in self._messages)

    def _put(self, message: Message) -> None:
        with self._lock:
            if len(self._messages) >= self.capacity:
                raise InboxOverflowError(f"Inbox for '{self.owner}' is full")
            self._messages.append(message)

    def poll(self, limit: Optional[int] = None, include_read: bool = False) -> List[Message]:
        """Return queued messages in delivery order without removing them."""
        if limit is not None and limit < 0:
            raise ValueError("limit must not be negative")
        with self._lock:
            messages = [m for m in self._messages if include_read or m.message_id not in self._read]
            return messages if limit is None else messages[:limit]

    def mark_read(self, message_id: str) -> bool:
        """Mark a queued message read, returning whether it was found."""
        with self._lock:
            if not any(m.message_id == message_id for m in self._messages):
                return False
            self._read.add(message_id)
            return True

    def acknowledge(self, message_id: str) -> bool:
        """Remove a queued message, returning whether it was found."""
        with self._lock:
            for message in self._messages:
                if message.message_id == message_id:
                    self._messages.remove(message)
                    self._read.discard(message_id)
                    return True
            return False

    def stats(self) -> Dict[str, int]:
        """Return message counts for this inbox."""
        with self._lock:
            return {"messages": len(self._messages), "unread": self.unread_count}


class MessageBus:
    """Low-latency local bus with atomic global delivery ordering."""

    def __init__(self, default_capacity: int = 1000) -> None:
        self.default_capacity = default_capacity
        self._inboxes: Dict[str, VirtualInbox] = {}
        self._lock = threading.RLock()
        self._sequence = 0
        self._messages_sent = 0
        self._broadcasts_sent = 0
        self._broadcast_deliveries = 0

    def register_inbox(self, owner: str, capacity: Optional[int] = None) -> VirtualInbox:
        """Register and return an agent's inbox."""
        with self._lock:
            inbox = VirtualInbox(owner, capacity or self.default_capacity)
            self._inboxes[owner] = inbox
            return inbox

    def deregister_inbox(self, owner: str) -> Optional[VirtualInbox]:
        """Remove an agent inbox and return it, if registered."""
        with self._lock:
            return self._inboxes.pop(owner, None)

    def has_inbox(self, owner: str) -> bool:
        """Return whether an agent has a registered inbox."""
        with self._lock:
            return owner in self._inboxes

    def get_inbox(self, owner: str) -> Optional[VirtualInbox]:
        """Return an agent inbox, or ``None`` when it is not registered."""
        with self._lock:
            return self._inboxes.get(owner)

    def _deliver(self, sender: str, recipient: str, body: Any, kind: MessageKind,
                 metadata: Optional[Dict[str, Any]] = None, priority: int = 0) -> Message:
        with self._lock:
            inbox = self._inboxes.get(recipient)
            if inbox is None:
                raise InboxNotFoundError(f"No virtual inbox registered for '{recipient}'")
            self._sequence += 1
            message = Message(sender, recipient, body, kind, priority=priority, sequence=self._sequence,
                              metadata=dict(metadata or {}))
            inbox._put(message)
            self._messages_sent += 1
            return message

    def send(self, sender: str, recipient: str, body: Any,
             metadata: Optional[Dict[str, Any]] = None, priority: int = 0) -> Message:
        """Send one direct message and return the delivered message."""
        return self._deliver(sender, recipient, body, MessageKind.DIRECT, metadata, priority)

    def broadcast(self, sender: str, body: Any,
                  metadata: Optional[Dict[str, Any]] = None, priority: int = 0) -> List[Message]:
        """Deliver a broadcast to every registered inbox except the sender."""
        with self._lock:
            recipients = [owner for owner in self._inboxes if owner != sender]
            messages = [self._deliver(sender, owner, body, MessageKind.BROADCAST, metadata, priority)
                        for owner in recipients]
            self._broadcasts_sent += 1
            self._broadcast_deliveries += len(messages)
            return messages

    def stats(self) -> Dict[str, int]:
        """Return aggregate bus counters and current inbox count."""
        with self._lock:
            return {"inboxes": len(self._inboxes), "messages_sent": self._messages_sent,
                    "broadcasts_sent": self._broadcasts_sent,
                    "broadcast_deliveries": self._broadcast_deliveries}

    def reset(self) -> None:
        """Clear counters and all queued messages while retaining inboxes."""
        with self._lock:
            for inbox in self._inboxes.values():
                inbox._messages.clear()
                inbox._read.clear()
            self._sequence = self._messages_sent = self._broadcasts_sent = self._broadcast_deliveries = 0
