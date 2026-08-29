from honeynet.database import StoredEvent


def stored_event_dict(event: StoredEvent) -> dict:
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "timestamp": event.timestamp.isoformat(),
        "sensor_id": event.sensor_id,
        "session_id": event.session_id,
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "data": event.data,
        "source_event": event.source_event,
    }
