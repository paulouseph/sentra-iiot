"""
schema.py
---------
Feature-space definition for the Edge-IIoTset corpus.

Two things matter here and both are easy to get wrong.

1. Leakage. Edge-IIoTset ships raw capture artefacts -- timestamps, host
   addresses, full URIs, raw payloads. A tree model will happily memorise
   "ip.src_host == 192.168.0.152 implies Backdoor" and report 99.9% accuracy
   that means nothing. DROP_COLUMNS removes them. This is the single biggest
   reason v1's numbers looked too good.

2. Legibility. A column called `tcp.connection.synack` means nothing to an
   analyst reading an alert at 3am. FRIENDLY_NAMES maps every retained column
   to a phrase a human can act on, which is what the explanation layer renders.
"""
from __future__ import annotations

# Columns removed before training. The first group is direct identity leakage,
# the second is raw payload content that encodes the label almost verbatim.
DROP_COLUMNS: list[str] = [
    # identity / timing leakage
    "frame.time",
    "ip.src_host",
    "ip.dst_host",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "icmp.transmit_timestamp",
    "tcp.srcport",
    "tcp.dstport",
    "udp.port",
    "tcp.seq",
    "tcp.ack_raw",
    "tcp.checksum",
    "icmp.checksum",
    "mbtcp.trans_id",
    "udp.stream",
    # raw payload content
    "http.file_data",
    "http.request.full_uri",
    "http.request.uri.query",
    "tcp.options",
    "tcp.payload",
    "mqtt.msg",
    "dns.qry.name",
    # label columns
    "Attack_label",
    "Attack_type",
]

LABEL_COLUMN = "Attack_type"

# Columns that survive cleaning but are categorical strings rather than numbers.
CATEGORICAL_COLUMNS: list[str] = [
    "http.request.method",
    "http.referer",
    "http.request.version",
    "dns.qry.name.len",
    "mqtt.conack.flags",
    "mqtt.protoname",
    "mqtt.topic",
    "mqtt.msg_decoded_as",
]

# Human-readable rendering for the alert explanation panel. Anything not in
# this table falls back to a tidied version of the raw column name.
FRIENDLY_NAMES: dict[str, str] = {
    "arp.opcode": "ARP message type",
    "arp.hw.size": "ARP hardware address size",
    "icmp.seq_le": "ICMP sequence number",
    "icmp.unused": "ICMP padding bytes",
    "http.content_length": "HTTP body size",
    "http.request.method": "HTTP method",
    "http.referer": "HTTP referer header",
    "http.request.version": "HTTP version",
    "http.response": "HTTP response flag",
    "http.tls_port": "TLS port in use",
    "tcp.ack": "TCP acknowledgement flag",
    "tcp.connection.fin": "TCP connections closing",
    "tcp.connection.rst": "TCP connections reset",
    "tcp.connection.syn": "TCP half-open connections",
    "tcp.connection.synack": "TCP handshake completions",
    "tcp.flags": "TCP control flags",
    "tcp.flags.ack": "TCP ACK flag set",
    "tcp.len": "TCP payload length",
    "udp.time_delta": "Gap between UDP packets",
    "dns.qry.name.len": "DNS query name length",
    "dns.qry.qu": "DNS unicast-response flag",
    "dns.qry.type": "DNS record type",
    "dns.retransmission": "DNS retransmissions",
    "dns.retransmit_request": "DNS repeat requests",
    "dns.retransmit_request_in": "DNS repeat request window",
    "mqtt.conack.flags": "MQTT connection acknowledgement",
    "mqtt.conflag.cleansess": "MQTT clean-session flag",
    "mqtt.conflags": "MQTT connect flags",
    "mqtt.hdrflags": "MQTT header flags",
    "mqtt.len": "MQTT message length",
    "mqtt.msgtype": "MQTT message type",
    "mqtt.proto_len": "MQTT protocol name length",
    "mqtt.protoname": "MQTT protocol name",
    "mqtt.topic": "MQTT topic",
    "mqtt.topic_len": "MQTT topic length",
    "mqtt.ver": "MQTT version",
    "mbtcp.len": "Modbus/TCP frame length",
    "mbtcp.unit_id": "Modbus unit address",
    # synthetic-fallback columns
    "packet_rate": "Packets per second",
    "packet_size": "Average packet size",
    "avg_iat_ms": "Gap between packets",
    "unique_dst_ports": "Distinct ports contacted",
    "payload_entropy": "Payload randomness",
    "ttl": "Time-to-live",
    "duration_ms": "Flow duration",
    "src_bytes": "Bytes sent",
    "dst_bytes": "Bytes received",
    "flow_count": "Concurrent flows",
    "syn_flag_count": "SYN flags seen",
}

# Units used when the explanation panel prints an observed value.
UNITS: dict[str, str] = {
    "packet_rate": "pkt/s",
    "packet_size": "bytes",
    "avg_iat_ms": "ms",
    "duration_ms": "ms",
    "src_bytes": "bytes",
    "dst_bytes": "bytes",
    "http.content_length": "bytes",
    "tcp.len": "bytes",
    "mqtt.len": "bytes",
    "mbtcp.len": "bytes",
    "udp.time_delta": "s",
}


def friendly(column: str) -> str:
    """Render a column name the way an analyst would say it out loud."""
    if column in FRIENDLY_NAMES:
        return FRIENDLY_NAMES[column]
    cleaned = column.replace("_", " ").replace(".", " ")
    return cleaned[:1].upper() + cleaned[1:]


def unit(column: str) -> str:
    return UNITS.get(column, "")
