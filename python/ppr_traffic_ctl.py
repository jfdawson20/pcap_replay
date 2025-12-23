#!/usr/bin/env python3
"""
ppr_traffic_ctl.py - Friendly Python wrapper for PPR Traffic / PCAP replay JSON-RPC API.

This mirrors the style of your ppr_acl.py and uses WpsControlClient from ppr_cli.py.

Commands implemented (from your C RPC table):
  - ppr_get_loaded_pcaps_list
  - ppr_load_pcap_file
  - ppr_assign_port_slot
  - ppr_cmd_get_port_list
  - ppr_port_tx_ctl
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from prettytable import PrettyTable

from ppr_cli import WpsControlClient, WpsControlError  # adjust path if needed


# ---------------------------------------------------------------------------
# Wire command names
# ---------------------------------------------------------------------------

CMD_GET_LOADED_PCAPS_LIST = "ppr_get_loaded_pcaps_list"
CMD_LOAD_PCAP_FILE = "ppr_load_pcap_file"
CMD_ASSIGN_PORT_SLOT = "ppr_assign_port_slot"

CMD_GET_PORT_LIST = "ppr_cmd_get_port_list"
CMD_PORT_TX_CTL = "ppr_port_tx_ctl"


# ---------------------------------------------------------------------------
# Optional enums / helpers
# ---------------------------------------------------------------------------

PACE_MODE_NAME_TO_ID: Dict[str, int] = {
    # These are placeholders; update if you have specific C enum values.
    "disabled": 0,
    "asap": 0,
    "realtime": 1,
    "pps": 2,
}
START_MODE_NAME_TO_ID: Dict[str, int] = {
    # Placeholders; update to your C enum values.
    "immediate": 0,
    "armed": 1,
    "manual": 2,
}


def _maybe_int(s: Optional[str]) -> Optional[int]:
    if s is None:
        return None
    return int(s, 0) if isinstance(s, str) else int(s)


def _resolve_pace_mode(value: str) -> int:
    # allow int like "2" or "0x2"
    try:
        return int(value, 0)
    except ValueError:
        pass
    key = value.strip().lower()
    if key not in PACE_MODE_NAME_TO_ID:
        raise ValueError(
            f"Unknown pace_mode '{value}'. Use an int or one of: {', '.join(sorted(PACE_MODE_NAME_TO_ID))}"
        )
    return int(PACE_MODE_NAME_TO_ID[key])


def _resolve_start_mode(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        pass
    key = value.strip().lower()
    if key not in START_MODE_NAME_TO_ID:
        raise ValueError(
            f"Unknown start_mode '{value}'. Use an int or one of: {', '.join(sorted(START_MODE_NAME_TO_ID))}"
        )
    return int(START_MODE_NAME_TO_ID[key])


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


# ---------------------------------------------------------------------------
# High-level client wrapper
# ---------------------------------------------------------------------------

class PprTrafficClient:
    """
    High-level wrapper around Traffic / PCAP replay JSON-RPC commands.
    """

    def __init__(self, ctl: WpsControlClient) -> None:
        self.ctl = ctl

    def get_loaded_pcaps_list(self) -> Dict[str, Any]:
        return self.ctl.call(CMD_GET_LOADED_PCAPS_LIST)

    def load_pcap_file(self, filename: str) -> Dict[str, Any]:
        return self.ctl.call(CMD_LOAD_PCAP_FILE, args={"filename": filename})

    def assign_port_slot(
        self,
        port: str,
        slotid: int,
        pace_mode: int,
        start_mode: int,
        fixed_index: int,
        replay_window_sec: int,
    ) -> Dict[str, Any]:
        payload = {
            "port": port,
            "slotid": int(slotid),
            "pace_mode": int(pace_mode),
            "start_mode": int(start_mode),
            "fixed_index": int(fixed_index),
            "replay_window_sec": int(replay_window_sec),
        }
        return self.ctl.call(CMD_ASSIGN_PORT_SLOT, args=payload)

    def get_port_list(self) -> Dict[str, Any]:
        return self.ctl.call(CMD_GET_PORT_LIST)

    def port_tx_ctl(self, port: str, cmd: str) -> Dict[str, Any]:
        cmd_l = cmd.strip().lower()
        if cmd_l not in ("enable", "disable"):
            raise ValueError("cmd must be 'enable' or 'disable'")
        return self.ctl.call(CMD_PORT_TX_CTL, args={"port": port, "cmd": cmd_l})


# ---------------------------------------------------------------------------
# Pretty display helpers (tolerant to schema variations)
# ---------------------------------------------------------------------------

def display_ports(reply: Dict[str, Any]) -> None:
    """
    Try to render port list no matter what the exact JSON shape is.
    Common shapes seen in these systems:
      - {"ports": [ {...}, {...} ]}
      - {"port_list": [ ... ]}
      - {"results": [ ... ]}
    """
    ports = (
        reply.get("ports")
        or reply.get("port_list")
        or reply.get("results")
        or reply.get("data")
        or []
    )
    ports = _as_list(ports)

    t = PrettyTable()
    t.field_names = ["Port", "Type", "Port ID", "RXQ", "TXQ", "Link", "MTU", "Notes"]

    for p in ports:
        if not isinstance(p, dict):
            t.add_row([str(p), "", "", "", "", "", "", ""])
            continue

        name = p.get("name") or p.get("port") or p.get("port_name") or ""
        ptype = p.get("type") or p.get("port_type") or ""
        port_id = p.get("port_id", p.get("id", ""))
        rxq = p.get("rxq", p.get("rx_queues", ""))
        txq = p.get("txq", p.get("tx_queues", ""))
        link = p.get("link") or p.get("link_status") or p.get("up") or ""
        mtu = p.get("mtu", "")
        notes = p.get("notes", "")

        t.add_row([name, ptype, port_id, rxq, txq, link, mtu, notes])

    print("Ports:")
    print(t)
    print("")


def display_loaded_pcaps(reply: Dict[str, Any]) -> None:
    """
    Render loaded pcaps list. Common shapes:
      - {"slots":[ {...}, ... ]}
      - {"pcaps":[ {...}, ... ]}
      - {"loaded":[ {...}, ... ]}
    """
    slots = (
        reply.get("slots")
        or reply.get("pcaps")
        or reply.get("loaded")
        or reply.get("results")
        or []
    )
    slots = _as_list(slots)

    t = PrettyTable()
    t.field_names = ["Slot ID", "Filename", "Packets", "Bytes", "Loaded", "Notes"]

    for s in slots:
        if not isinstance(s, dict):
            t.add_row(["", str(s), "", "", "", ""])
            continue

        slotid = s.get("slotid", s.get("slot_id", s.get("id", "")))
        filename = s.get("filename", s.get("file", s.get("path", "")))
        packets = s.get("packets", s.get("pkt_count", s.get("num_pkts", "")))
        bytes_ = s.get("bytes", s.get("byte_count", s.get("num_bytes", "")))
        loaded = s.get("loaded", s.get("is_loaded", ""))
        notes = s.get("notes", "")

        t.add_row([slotid, filename, packets, bytes_, loaded, notes])

    print("Loaded PCAPs:")
    print(t)
    print("")


def display_generic_reply(title: str, reply: Dict[str, Any]) -> None:
    t = PrettyTable()
    t.field_names = ["Key", "Value"]
    for k in sorted(reply.keys()):
        t.add_row([k, reply[k]])
    print(f"{title}:")
    print(t)
    print("")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="PPR Traffic / PCAP replay control client")

    p.add_argument("-p", "--port", type=int, default=9000, help="RPC Server Port")
    p.add_argument("-i", "--hostip", type=str, default="localhost", help="RPC Server Address")

    sp = p.add_subparsers(dest="command", required=True)

    # ---- ports ----
    sp.add_parser("ports", help="List all ports configured in the application")

    p_tx = sp.add_parser("tx", help="Enable or disable transmission on a port")
    p_tx.add_argument("portname", help="Port name")
    p_tx.add_argument("cmd", choices=["enable", "disable"], help="TX control")

    # ---- pcaps ----
    sp.add_parser("pcaps", help="List loaded pcap files in memory")

    p_load = sp.add_parser("load", help="Load a pcap file into memory")
    p_load.add_argument("filename", help="Path to pcap file")

    # ---- assign ----
    p_asg = sp.add_parser("assign", help="Assign a loaded pcap slot to a port for replay")
    p_asg.add_argument("--port", required=True, help="Port name")
    p_asg.add_argument("--slotid", required=True, type=int, help="Loaded pcap slot id")

    # allow either numeric or string mode
    p_asg.add_argument(
        "--pace-mode",
        default="0",
        help="pace_mode (int or name). Examples: 0, 1, realtime, pps",
    )
    p_asg.add_argument(
        "--start-mode",
        default="0",
        help="start_mode (int or name). Examples: 0, 1, immediate, armed",
    )
    p_asg.add_argument(
        "--fixed-index",
        type=int,
        default=0,
        help="fixed_index (int). Use for deterministic selection if supported.",
    )
    p_asg.add_argument(
        "--replay-window-sec",
        type=int,
        default=0,
        help="replay_window_sec (int). 0 typically means 'no window' if supported.",
    )

    return p


def main() -> int:
    args = build_parser().parse_args()

    ctl = WpsControlClient(port=args.port, hostip=args.hostip)
    traffic = PprTrafficClient(ctl)

    try:
        if args.command == "ports":
            reply = traffic.get_port_list()
            display_ports(reply)
            return 0

        if args.command == "tx":
            reply = traffic.port_tx_ctl(args.portname, args.cmd)
            display_generic_reply("TX Control Reply", reply)
            return 0

        if args.command == "pcaps":
            reply = traffic.get_loaded_pcaps_list()
            display_loaded_pcaps(reply)
            return 0

        if args.command == "load":
            reply = traffic.load_pcap_file(args.filename)
            # Often returns assigned slot id; print both pretty and a short line.
            display_generic_reply("Load PCAP Reply", reply)
            if "slotid" in reply:
                print(f"Loaded '{args.filename}' into slotid={reply['slotid']}")
            elif "slot_id" in reply:
                print(f"Loaded '{args.filename}' into slotid={reply['slot_id']}")
            return 0

        if args.command == "assign":
            pace_mode = _resolve_pace_mode(args.pace_mode)
            start_mode = _resolve_start_mode(args.start_mode)

            reply = traffic.assign_port_slot(
                port=args.port,
                slotid=args.slotid,
                pace_mode=pace_mode,
                start_mode=start_mode,
                fixed_index=args.fixed_index,
                replay_window_sec=args.replay_window_sec,
            )
            display_generic_reply("Assign Port Slot Reply", reply)
            return 0

        raise RuntimeError(f"Unknown command: {args.command}")

    except (WpsControlError, ValueError) as e:
        print(f"ERROR: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
