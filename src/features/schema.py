"""Canonical feature schema — the contract between training and live detection.

The sensor can only ever see ONE direction of a conversation (it sits behind a
data diode), so the model is trained exclusively on features that are
observable in the forward (sender -> receiver) stream of CIC-IDS2017 flows.

`CANONICAL_FEATURES` is the authoritative list. The dataset loader maps
CICFlowMeter column names onto it via aliases (handling the naming drift
between the MachineLearningCVE / TrafficLabelling variants); the live flow
accumulator computes the same features directly from sniffed packets.
"""
from __future__ import annotations

import re

BENIGN = "BENIGN"

# --------------------------------------------------------------------------
# Canonical features (order matters — model input vector follows this list)
# --------------------------------------------------------------------------

CANONICAL_FEATURES: list[str] = [
    "protocol",                # IP protocol number (6=TCP, 17=UDP, 0=other)
    "duration_us",             # Flow Duration (microseconds)
    "fwd_packets",             # Total Fwd Packets
    "fwd_bytes",               # Total Length of Fwd Packets
    "fwd_pkt_len_max",
    "fwd_pkt_len_min",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_std",
    "flow_bytes_per_s",        # Flow Bytes/s
    "flow_packets_per_s",      # Flow Packets/s
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_iat_min",
    "fwd_iat_tot",             # Fwd IAT Total
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_max",
    "fwd_iat_min",
    "fwd_psh_flags",
    "fwd_urg_flags",
    "fwd_header_bytes",        # Fwd Header Length (sum of L3+L4 header bytes)
    "fwd_packets_per_s",       # Fwd Packets/s
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "urg_flag_count",
    "cwr_flag_count",          # CICFlowMeter calls this "CWE Flag Count"
    "ece_flag_count",
    "fwd_seg_size_avg",        # Avg Fwd Segment Size
    "init_win_bytes_fwd",      # Init_Win_bytes_forward
    "act_data_pkt_fwd",        # packets carrying payload
    "min_seg_size_fwd",        # min_seg_size_forward
    "active_mean",
    "active_std",
    "active_max",
    "active_min",
    "idle_mean",
    "idle_std",
    "idle_max",
    "idle_min",
]

# canonical name -> normalised dataset column names it can be sourced from.
# "Fwd IAT Total" (TrafficLabelling) and "Fwd IAT Tot" (MachineLearningCVE),
# "Avg Fwd Segment Size" vs "Fwd Segment Size Avg", the duplicated
# "Fwd Header Length" column, etc. are all handled here.
_FEATURE_ALIASES: dict[str, tuple[str, ...]] = {
    "protocol":            ("protocol",),
    "duration_us":         ("flow duration",),
    "fwd_packets":         ("total fwd packets", "total fwd packet"),
    "fwd_bytes":           ("total length of fwd packets", "totlen fwd packets"),
    "fwd_pkt_len_max":     ("fwd packet length max",),
    "fwd_pkt_len_min":     ("fwd packet length min",),
    "fwd_pkt_len_mean":    ("fwd packet length mean",),
    "fwd_pkt_len_std":     ("fwd packet length std",),
    "flow_bytes_per_s":    ("flow bytes s", "flow bytes per s"),
    "flow_packets_per_s":  ("flow packets s", "flow packets per s"),
    "flow_iat_mean":       ("flow iat mean",),
    "flow_iat_std":        ("flow iat std",),
    "flow_iat_max":        ("flow iat max",),
    "flow_iat_min":        ("flow iat min",),
    "fwd_iat_tot":         ("fwd iat total", "fwd iat tot"),
    "fwd_iat_mean":        ("fwd iat mean",),
    "fwd_iat_std":         ("fwd iat std",),
    "fwd_iat_max":         ("fwd iat max",),
    "fwd_iat_min":         ("fwd iat min",),
    "fwd_psh_flags":       ("fwd psh flags",),
    "fwd_urg_flags":       ("fwd urg flags",),
    "fwd_header_bytes":    ("fwd header length", "fwd header length duplicated 0",
                            "fwd header length 1", "fwd header len"),
    "fwd_packets_per_s":   ("fwd packets s", "fwd packets per s"),
    "fin_flag_count":      ("fin flag count",),
    "syn_flag_count":      ("syn flag count",),
    "rst_flag_count":      ("rst flag count",),
    "psh_flag_count":      ("psh flag count",),
    "ack_flag_count":      ("ack flag count",),
    "urg_flag_count":      ("urg flag count",),
    "cwr_flag_count":      ("cwe flag count", "cwr flag count"),
    "ece_flag_count":      ("ece flag count",),
    "fwd_seg_size_avg":    ("avg fwd segment size", "fwd segment size avg"),
    "init_win_bytes_fwd":  ("init win bytes forward",),
    "act_data_pkt_fwd":    ("act data pkt fwd",),
    "min_seg_size_fwd":    ("min seg size forward",),
    "active_mean":         ("active mean",),
    "active_std":          ("active std",),
    "active_max":           ("active max",),
    "active_min":          ("active min",),
    "idle_mean":           ("idle mean",),
    "idle_std":            ("idle std",),
    "idle_max":            ("idle max",),
    "idle_min":            ("idle min",),
}

# Columns that carry the label in the various CSV/parquet variants.
_LABEL_ALIASES = ("label", "labels", "attack name", "attack category")


def normalize_key(name: str) -> str:
    """Normalise a dataset column name: lowercase, alphanumeric runs + single spaces.

    'Init_Win_bytes_forward' -> 'init win bytes forward'
    'Flow Bytes/s'           -> 'flow bytes s'
    """
    return re.sub(r"[^0-9a-zA-Z]+", " ", name).strip().lower()


def canonical_column_map(columns: list[str]) -> dict[str, str]:
    """Map canonical feature names to concrete column names present in ``columns``.

    Returns {canonical_name: original_column_name}. Raises KeyError with a
    helpful message when a canonical feature cannot be sourced.
    """
    norm_to_orig: dict[str, str] = {}
    for col in columns:
        norm_to_orig.setdefault(normalize_key(col), col)

    mapping: dict[str, str] = {}
    missing: list[str] = []
    for canonical in CANONICAL_FEATURES:
        # try the canonical name itself first (e.g. data exported by this
        # pipeline), then the known CICFlowMeter naming variants
        candidates = (normalize_key(canonical),) + _FEATURE_ALIASES[canonical]
        found = None
        for alias in candidates:
            if alias in norm_to_orig:
                found = norm_to_orig[alias]
                break
        if found is None:
            missing.append(canonical)
        else:
            mapping[canonical] = found
    if missing:
        raise KeyError(
            f"dataset is missing {len(missing)} canonical feature column(s): {missing}. "
            f"Available columns: {list(columns)[:20]}..."
        )
    return mapping


def find_label_column(columns: list[str]) -> str:
    for alias in _LABEL_ALIASES:
        for col in columns:
            if normalize_key(col) == alias:
                return col
    raise KeyError(f"no label column found among: {list(columns)[:20]}...")


# --------------------------------------------------------------------------
# Label normalisation / taxonomy
# --------------------------------------------------------------------------

_LABEL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^benign$"), BENIGN),
    (re.compile(r"^ddos$"), "DDoS"),
    (re.compile(r"^portscan$"), "PortScan"),
    (re.compile(r"^bot$"), "Bot"),
    (re.compile(r"^infiltration$"), "Infiltration"),
    (re.compile(r"^heartbleed$"), "Heartbleed"),
    (re.compile(r"^dos hulk$"), "DoS Hulk"),
    (re.compile(r"^dos goldeneye$"), "DoS GoldenEye"),
    (re.compile(r"^dos slowloris$"), "DoS slowloris"),
    (re.compile(r"^dos slowhttptest$"), "DoS Slowhttptest"),
    (re.compile(r"^ftp patator$"), "FTP-Patator"),
    (re.compile(r"^ssh patator$"), "SSH-Patator"),
    (re.compile(r"^web attack xss$"), "Web Attack - XSS"),
    (re.compile(r"^web attack sql injection$"), "Web Attack - SQL Injection"),
    (re.compile(r"^web attack brute force$"), "Web Attack - Brute Force"),
]


def normalize_label(raw: object) -> str:
    """Normalise a dataset label (handles en-dashes, casing, extra spaces)."""
    text = normalize_key(str(raw))
    for pattern, canonical in _LABEL_PATTERNS:
        if pattern.match(text):
            return canonical
    if not text:
        return "UNKNOWN"
    return text  # unknown labels are kept as their own (normalised) class


_LABEL_CATEGORY: dict[str, str] = {
    BENIGN: "benign",
    "DDoS": "dos",
    "DoS Hulk": "dos",
    "DoS GoldenEye": "dos",
    "DoS slowloris": "dos",
    "DoS Slowhttptest": "dos",
    "Heartbleed": "exploit",
    "PortScan": "reconnaissance",
    "Bot": "botnet",
    "Infiltration": "infiltration",
    "Web Attack - Brute Force": "web-attack",
    "Web Attack - XSS": "web-attack",
    "Web Attack - SQL Injection": "web-attack",
    "FTP-Patator": "brute-force",
    "SSH-Patator": "brute-force",
}

_LABEL_SEVERITY: dict[str, str] = {
    BENIGN: "none",
    "PortScan": "low",
    "FTP-Patator": "medium",
    "SSH-Patator": "medium",
    "Bot": "high",
    "Web Attack - Brute Force": "high",
    "Web Attack - XSS": "high",
    "Web Attack - SQL Injection": "critical",
    "DDoS": "critical",
    "DoS Hulk": "critical",
    "DoS GoldenEye": "critical",
    "DoS slowloris": "high",
    "DoS Slowhttptest": "high",
    "Infiltration": "critical",
    "Heartbleed": "critical",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def is_threat_label(label: str) -> bool:
    return label != BENIGN


def category_for(label: str) -> str:
    if label in _LABEL_CATEGORY:
        return _LABEL_CATEGORY[label]
    if is_threat_label(label):
        return "unknown-threat"
    return "benign"


def severity_for(label: str) -> str:
    if label in _LABEL_SEVERITY:
        return _LABEL_SEVERITY[label]
    return "medium" if is_threat_label(label) else "none"
