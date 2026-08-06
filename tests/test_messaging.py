import pytest

from local_agent_sandbox.messaging import (
    Message,
    MessageBus,
    MessageKind,
    InboxNotFoundError,
    InboxOverflowError,
)


def test_direct_and_broadcast_delivery_are_ordered():
    """Messages are delivered to virtual inboxes in bus sequence order."""
    bus = MessageBus()
    bus.register_inbox("alpha")
    bus.register_inbox("beta")

    direct = bus.send("alpha", "beta", "ping")
    broadcast = bus.broadcast("alpha", "standup")

    received = bus.get_inbox("beta").poll()
    assert [message.body for message in received] == ["ping", "standup"]
    assert received[0].kind is MessageKind.DIRECT
    assert received[1].sequence > direct.sequence
    # Broadcasts are not delivered back to the sender.
    assert len(bus.get_inbox("alpha").poll()) == 0
    assert len(broadcast) == 1
    assert broadcast[0].recipient == "beta"


def test_broadcast_reaches_multiple_inboxes_except_sender():
    """A broadcast fans out to every registered inbox except the sender."""
    bus = MessageBus()
    bus.register_inbox("a")
    bus.register_inbox("b")
    bus.register_inbox("c")

    messages = bus.broadcast("a", "hello")
    recipients = {m.recipient for m in messages}

    assert recipients == {"b", "c"}
    assert all(m.kind is MessageKind.BROADCAST for m in messages)
    assert bus.get_inbox("a").poll() == []
    assert len(bus.get_inbox("b").poll()) == 1
    assert len(bus.get_inbox("c").poll()) == 1


def test_send_to_unknown_inbox_raises():
    """Sending a direct message to an unregistered inbox raises InboxNotFoundError."""
    bus = MessageBus()
    bus.register_inbox("alpha")
    with pytest.raises(InboxNotFoundError):
        bus.send("alpha", "unknown", "ping")


def test_inbox_capacity_enforced():
    """An inbox raises InboxOverflowError when its capacity is exceeded."""
    bus = MessageBus()
    bus.register_inbox("alpha", capacity=2)
    bus.register_inbox("beta", capacity=2)

    bus.send("alpha", "beta", "one")
    bus.send("alpha", "beta", "two")

    with pytest.raises(InboxOverflowError):
        bus.send("alpha", "beta", "three")


def test_virtual_inbox_poll_mark_read_acknowledge():
    """Inbox supports polling, read tracking, and acknowledgement."""
    bus = MessageBus()
    bus.register_inbox("alpha")
    bus.register_inbox("beta")

    m1 = bus.send("alpha", "beta", "first")
    m2 = bus.send("alpha", "beta", "second")

    inbox = bus.get_inbox("beta")
    assert inbox.unread_count == 2

    polled = inbox.poll()
    assert len(polled) == 2
    assert [m.body for m in polled] == ["first", "second"]
    assert inbox.unread_count == 2

    assert inbox.mark_read(m1.message_id) is True
    assert inbox.unread_count == 1
    assert inbox.mark_read(m1.message_id) is True
    assert inbox.mark_read("missing") is False

    unread = inbox.poll()
    assert len(unread) == 1
    assert unread[0].body == "second"

    assert inbox.acknowledge(m2.message_id) is True
    assert inbox.acknowledge(m2.message_id) is False
    assert inbox.poll() == []


def test_message_serialization_roundtrip():
    """Messages can be serialized to and restored from dictionaries."""
    original = Message.direct("a", "b", {"key": "value"}, metadata={"tag": "test"})
    data = original.to_dict()
    restored = Message.from_dict(data)

    assert restored == original
    assert restored.to_dict() == data
    assert restored.kind is MessageKind.DIRECT
    assert restored.metadata == {"tag": "test"}


def test_bus_stats_and_reset():
    """The bus exposes aggregate counters and can reset them."""
    bus = MessageBus()
    bus.register_inbox("a")
    bus.register_inbox("b")
    bus.register_inbox("c")

    bus.send("a", "b", "direct")
    bus.broadcast("a", "broadcast")

    stats = bus.stats()
    assert stats["inboxes"] == 3
    assert stats["messages_sent"] == 3  # 1 direct + 2 broadcast deliveries
    assert stats["broadcasts_sent"] == 1
    assert stats["broadcast_deliveries"] == 2

    bus.reset()
    stats = bus.stats()
    assert stats["messages_sent"] == 0
    assert stats["broadcasts_sent"] == 0
    assert stats["broadcast_deliveries"] == 0
    assert bus.get_inbox("b").poll() == []
    assert bus.get_inbox("c").poll() == []
    # Inboxes themselves are retained after reset.
    assert bus.has_inbox("a")


def test_priority_and_metadata_preserved():
    """Priority and metadata are preserved on delivered messages."""
    bus = MessageBus()
    bus.register_inbox("alpha")
    bus.register_inbox("beta")

    msg = bus.send("alpha", "beta", "body", metadata={"foo": "bar"}, priority=7)
    assert msg.priority == 7
    assert msg.metadata == {"foo": "bar"}
