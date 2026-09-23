"""
assets.py
---------
A small, fixed inventory of the plant SENTRA-IIoT is watching.

An IP address is not an asset. "10.0.3.44 is showing ransomware behaviour"
makes an analyst go and look something up; "Line 2 engineering workstation is
showing ransomware behaviour" makes them move. Every alert is bound to one of
these records so the dashboard can speak in equipment, zones and consequences.

Zones follow the Purdue model, which is the vocabulary an OT engineer already
uses. Criticality drives how the dashboard sorts competing alerts of the same
severity: a critical on a safety controller outranks a critical on a badge
reader, and the interface should say so.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Asset:
    id: str
    name: str
    role: str
    ip: str
    zone: str           # Purdue level
    protocol: str
    criticality: int    # 1 = nice to have, 5 = people get hurt
    consequence: str    # what actually happens if this goes down

    def dict(self) -> dict:
        return asdict(self)


INVENTORY: list[Asset] = [
    Asset("plc-l1-01", "Line 1 fill controller", "PLC", "10.0.1.11",
          "Level 1 — Basic control", "Modbus/TCP", 5,
          "Filling stops mid-cycle; product in the line is scrapped."),
    Asset("plc-l2-01", "Line 2 capper controller", "PLC", "10.0.1.12",
          "Level 1 — Basic control", "Modbus/TCP", 5,
          "Caps mis-torque without alarming; a whole shift may need recall."),
    Asset("rtu-wtr-01", "Water treatment RTU", "RTU", "10.0.1.21",
          "Level 1 — Basic control", "Modbus/TCP", 5,
          "Dosing runs open-loop. This is the one that becomes a safety incident."),
    Asset("sen-tmp-07", "Kiln temperature array", "Sensor cluster", "10.0.2.31",
          "Level 2 — Area supervisory", "MQTT", 4,
          "Kiln control loses feedback and trips to a safe hold."),
    Asset("sen-vib-03", "Compressor vibration mesh", "Sensor cluster", "10.0.2.32",
          "Level 2 — Area supervisory", "MQTT", 3,
          "Predictive maintenance goes blind; failures become unplanned."),
    Asset("hmi-l1-01", "Line 1 operator HMI", "HMI", "10.0.2.41",
          "Level 2 — Area supervisory", "HTTP", 4,
          "Operators lose visibility and fall back to manual procedure."),
    Asset("gw-edge-01", "Plant edge gateway", "Gateway", "10.0.3.10",
          "Level 3 — Site operations", "HTTP/MQTT", 5,
          "Every northbound telemetry stream stops. Also the likeliest pivot point."),
    Asset("hist-01", "Process historian", "Historian", "10.0.3.20",
          "Level 3 — Site operations", "HTTP", 4,
          "Batch records stop being written — a compliance problem, not just an IT one."),
    Asset("eng-ws-02", "Engineering workstation", "Workstation", "10.0.3.44",
          "Level 3 — Site operations", "HTTP", 5,
          "Holds the PLC project files. Compromise here reaches every controller."),
    Asset("cam-gate-02", "Gatehouse camera bridge", "IP camera", "10.0.4.52",
          "Level 3.5 — DMZ", "HTTP", 2,
          "Loss of gate footage. Low process impact, common initial foothold."),
]

BY_ID: dict[str, Asset] = {a.id: a for a in INVENTORY}
BY_IP: dict[str, Asset] = {a.ip: a for a in INVENTORY}

# Which assets plausibly produce which kind of traffic. Keeps the live stream
# from putting a SQL injection on a temperature sensor.
AFFINITY: dict[str, list[str]] = {
    "DDoS_UDP": ["plc-l1-01", "plc-l2-01", "rtu-wtr-01", "sen-tmp-07"],
    "DDoS_ICMP": ["plc-l1-01", "rtu-wtr-01", "gw-edge-01", "sen-vib-03"],
    "DDoS_TCP": ["gw-edge-01", "hist-01", "hmi-l1-01", "plc-l2-01"],
    "DDoS_HTTP": ["hmi-l1-01", "gw-edge-01", "cam-gate-02", "hist-01"],
    "MITM": ["plc-l1-01", "plc-l2-01", "rtu-wtr-01", "hmi-l1-01"],
    "Port_Scanning": ["gw-edge-01", "cam-gate-02", "hist-01", "sen-vib-03"],
    "Vulnerability_scanner": ["gw-edge-01", "hist-01", "hmi-l1-01", "cam-gate-02"],
    "Fingerprinting": ["cam-gate-02", "sen-tmp-07", "gw-edge-01", "sen-vib-03"],
    "Backdoor": ["eng-ws-02", "gw-edge-01", "cam-gate-02"],
    "Ransomware": ["eng-ws-02", "hist-01"],
    "SQL_injection": ["hist-01", "gw-edge-01"],
    "XSS": ["hmi-l1-01", "cam-gate-02", "hist-01"],
    "Uploading": ["gw-edge-01", "hist-01", "eng-ws-02"],
    "Password": ["hmi-l1-01", "cam-gate-02", "gw-edge-01", "eng-ws-02"],
    "Normal": [a.id for a in INVENTORY],
}


def for_attack(attack_type: str, seed: str | None = None) -> Asset:
    """Pick a plausible asset for a class, deterministically when seeded."""
    candidates = AFFINITY.get(attack_type) or [a.id for a in INVENTORY]
    key = seed or attack_type
    index = int(hashlib.sha1(key.encode()).hexdigest(), 16) % len(candidates)
    return BY_ID[candidates[index]]


def for_ip(ip: str) -> Asset | None:
    return BY_IP.get(ip)


def inventory() -> list[dict]:
    return [a.dict() for a in INVENTORY]
