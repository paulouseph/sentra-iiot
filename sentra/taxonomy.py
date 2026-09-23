"""
taxonomy.py
-----------
The single source of truth for how SENTRA-IIoT talks about threats.

Edge-IIoTset (Ferrag et al., 2022) labels traffic with 15 fine-grained attack
types. A shift analyst does not think in 15 categories -- they think in
"is the plant safe, and what do I do in the next 60 seconds". So every raw
class carries three extra layers here:

    family    a six-way operational grouping (the taxonomy the SRS defines)
    severity  triage priority, which drives colour and sort order
    story     a plain-English sentence explaining what the model saw
    actions   what the analyst should actually do next

Keeping all of this in one table means the model, the API, the dashboard and
the report never disagree about what "Ransomware" means.
"""
from __future__ import annotations

from typing import TypedDict

# Order matters: this is the canonical class order used in confusion matrices
# and in the /api/model/card response.
ATTACK_TYPES: list[str] = [
    "Normal",
    "DDoS_UDP",
    "DDoS_ICMP",
    "DDoS_TCP",
    "DDoS_HTTP",
    "MITM",
    "Port_Scanning",
    "Vulnerability_scanner",
    "Fingerprinting",
    "Backdoor",
    "Ransomware",
    "SQL_injection",
    "XSS",
    "Uploading",
    "Password",
]

FAMILIES: list[str] = [
    "Normal",
    "Denial of service",
    "Interception",
    "Reconnaissance",
    "Malware",
    "Application abuse",
]

SEVERITIES: list[str] = ["info", "low", "medium", "high", "critical"]

SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}

# Hex values are mirrored in frontend/styles.css as --sev-* custom properties.
SEVERITY_COLOURS: dict[str, str] = {
    "info": "#3FBFA8",
    "low": "#56A8D8",
    "medium": "#E8A33D",
    "high": "#E8763D",
    "critical": "#E0475B",
}


class ThreatProfile(TypedDict):
    family: str
    severity: str
    headline: str
    story: str
    actions: list[str]
    mitre: str


PROFILES: dict[str, ThreatProfile] = {
    "Normal": {
        "family": "Normal",
        "severity": "info",
        "headline": "Routine plant traffic",
        "story": (
            "This flow looks like ordinary sensor-to-controller chatter. Packet "
            "sizes, timing and entropy all sit inside the baseline this device "
            "normally produces."
        ),
        "actions": ["No action needed. Kept for baseline statistics."],
        "mitre": "--",
    },
    "DDoS_UDP": {
        "family": "Denial of service",
        "severity": "critical",
        "headline": "UDP flood aimed at a controller",
        "story": (
            "A burst of small UDP datagrams is arriving far faster than this "
            "device can process. Left alone, the controller stops answering "
            "legitimate polls and the process loop goes blind."
        ),
        "actions": [
            "Rate-limit UDP toward the target at the cell switch",
            "Confirm the controller is still answering its SCADA master",
            "Trace the source port range upstream to the edge gateway",
        ],
        "mitre": "T0814 Denial of Service",
    },
    "DDoS_ICMP": {
        "family": "Denial of service",
        "severity": "critical",
        "headline": "ICMP flood saturating the segment",
        "story": (
            "Echo requests are hitting the segment at volumes no diagnostic tool "
            "would generate. This is bandwidth exhaustion, not troubleshooting."
        ),
        "actions": [
            "Drop inbound ICMP echo at the cell boundary",
            "Check whether neighbouring devices are also degraded",
            "Capture a 30-second PCAP before filtering, for the incident record",
        ],
        "mitre": "T0814 Denial of Service",
    },
    "DDoS_TCP": {
        "family": "Denial of service",
        "severity": "critical",
        "headline": "TCP SYN flood exhausting connections",
        "story": (
            "Half-open TCP connections are stacking up faster than they close. "
            "The device's connection table fills, and new sessions -- including "
            "the ones your HMI needs -- start getting refused."
        ),
        "actions": [
            "Enable SYN cookies or connection rate limits on the target",
            "Block the offending source range at the firewall",
            "Verify the HMI can still open a session to the controller",
        ],
        "mitre": "T0814 Denial of Service",
    },
    "DDoS_HTTP": {
        "family": "Denial of service",
        "severity": "high",
        "headline": "HTTP request flood against a device web interface",
        "story": (
            "The embedded web server on this device is being hammered with "
            "requests. Device web UIs are single-threaded and fall over quickly."
        ),
        "actions": [
            "Put the device web interface behind an access list",
            "Check whether the management VLAN is reachable from plant floor",
            "Confirm nobody has left the interface exposed to the corporate LAN",
        ],
        "mitre": "T0814 Denial of Service",
    },
    "MITM": {
        "family": "Interception",
        "severity": "high",
        "headline": "Someone is sitting between two devices",
        "story": (
            "ARP responses on this segment are inconsistent and round-trip times "
            "have jumped. That pattern means traffic is being relayed through an "
            "extra hop -- someone can read, and possibly alter, setpoints in transit."
        ),
        "actions": [
            "Compare the switch ARP table against your asset inventory",
            "Look for one MAC claiming two IPs, or one IP with two MACs",
            "Treat any setpoint change in the last hour as unverified",
        ],
        "mitre": "T0830 Adversary-in-the-Middle",
    },
    "Port_Scanning": {
        "family": "Reconnaissance",
        "severity": "low",
        "headline": "Something is mapping open ports",
        "story": (
            "A single source touched an unusual number of distinct ports in a "
            "short window. Nothing has been broken into yet -- this is the step "
            "that comes before an attempt."
        ),
        "actions": [
            "Identify the scanning host; if it is your own vulnerability scanner, whitelist it",
            "Watch this source for the next hour -- scans precede exploitation",
        ],
        "mitre": "T0842 Network Sniffing",
    },
    "Vulnerability_scanner": {
        "family": "Reconnaissance",
        "severity": "medium",
        "headline": "Automated vulnerability probing",
        "story": (
            "Requests carry the shape of scanner payloads -- repeated probes for "
            "known weak endpoints and default credentials. Someone is inventorying "
            "what is exploitable here."
        ),
        "actions": [
            "Confirm this is not a scheduled internal scan window",
            "Pull the list of endpoints probed and check each is patched",
            "If unscheduled, isolate the source host",
        ],
        "mitre": "T0846 Remote System Discovery",
    },
    "Fingerprinting": {
        "family": "Reconnaissance",
        "severity": "low",
        "headline": "Device identification attempt",
        "story": (
            "Crafted packets are being used to work out what operating system and "
            "firmware this device runs. It is quiet, slow, and deliberate."
        ),
        "actions": [
            "Note the source; fingerprinting usually precedes a targeted exploit",
            "Check that device banners are not leaking firmware versions",
        ],
        "mitre": "T0840 Network Connection Enumeration",
    },
    "Backdoor": {
        "family": "Malware",
        "severity": "critical",
        "headline": "Persistent remote-access channel",
        "story": (
            "This device is holding a long-lived outbound connection with high "
            "payload entropy -- encrypted traffic to somewhere it has no business "
            "talking to. That is a command-and-control channel."
        ),
        "actions": [
            "Isolate the device from the network now, before you investigate",
            "Preserve volatile memory if the device supports it",
            "Block the destination address across the whole plant, not just this cell",
        ],
        "mitre": "T0891 Hardcoded Credentials / C2",
    },
    "Ransomware": {
        "family": "Malware",
        "severity": "critical",
        "headline": "Ransomware behaviour on an engineering host",
        "story": (
            "Traffic shows bulk encrypted transfer alongside rapid file-share "
            "access. On an OT network this usually means an engineering "
            "workstation is encrypting what it can reach -- including project files."
        ),
        "actions": [
            "Disconnect the host physically; do not rely on a software block",
            "Verify the last known-good PLC program backup exists offline",
            "Escalate to the incident commander immediately",
        ],
        "mitre": "T0828 Loss of Productivity and Revenue",
    },
    "SQL_injection": {
        "family": "Application abuse",
        "severity": "high",
        "headline": "SQL injection against a historian or gateway",
        "story": (
            "Query strings contain SQL control characters where a device expected "
            "plain values. Someone is trying to read or alter the historian "
            "database directly."
        ),
        "actions": [
            "Check historian logs for queries returning unexpected row counts",
            "Confirm the gateway sanitises input, or put a WAF in front of it",
            "Rotate any database credentials the gateway holds",
        ],
        "mitre": "T0890 Exploitation for Privilege Escalation",
    },
    "XSS": {
        "family": "Application abuse",
        "severity": "medium",
        "headline": "Script injection into a device web page",
        "story": (
            "Script fragments are being submitted into fields that a device web "
            "interface later renders. The target is the engineer who opens that "
            "page next, not the device itself."
        ),
        "actions": [
            "Warn engineers away from the affected web interface until cleared",
            "Clear any stored values the interface renders back",
        ],
        "mitre": "T0862 Supply Chain Compromise",
    },
    "Uploading": {
        "family": "Application abuse",
        "severity": "high",
        "headline": "Unauthorised file upload",
        "story": (
            "A file is being pushed to a device endpoint that normally only "
            "serves data. Upload paths on industrial gateways are a common route "
            "to a web shell."
        ),
        "actions": [
            "Inspect the device filesystem for files newer than the last maintenance window",
            "Disable the upload endpoint if it is not required for operations",
        ],
        "mitre": "T0873 Project File Infection",
    },
    "Password": {
        "family": "Application abuse",
        "severity": "high",
        "headline": "Credential guessing against a device login",
        "story": (
            "Repeated authentication attempts are arriving faster than a human "
            "types. Industrial devices rarely lock accounts out, so this will keep "
            "going until it succeeds or you stop it."
        ),
        "actions": [
            "Block the source address at the cell firewall",
            "Check whether the account is still using its factory default password",
            "Review successful logins from this source in the last 24 hours",
        ],
        "mitre": "T0812 Default Credentials",
    },
}

# Convenience lookups -------------------------------------------------------

FAMILY_OF: dict[str, str] = {k: v["family"] for k, v in PROFILES.items()}
SEVERITY_OF: dict[str, str] = {k: v["severity"] for k, v in PROFILES.items()}


def profile(attack_type: str) -> ThreatProfile:
    """Return the analyst-facing profile for a class, with a safe fallback."""
    return PROFILES.get(
        attack_type,
        {
            "family": "Application abuse",
            "severity": "medium",
            "headline": f"Unrecognised classification: {attack_type}",
            "story": (
                "The model produced a label this build does not have a profile "
                "for. Treat it as unverified and review the raw features."
            ),
            "actions": ["Review the feature vector manually"],
            "mitre": "--",
        },
    )


def is_attack(attack_type: str) -> bool:
    return attack_type != "Normal"
