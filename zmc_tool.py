#!/usr/bin/env python3
"""zmc_tool.py — Zebra ZXP Series 7 host client for the ZMC1 protocol.

One command-line tool that runs every useful operation recovered from the
ZMC1 control plane of the Zebra ZXP Series 7 card printer (TCP/9100),
including the secure-action flow that enables duplex (2-sided) printing.

Every operation here is an OEM-supplied command: a ZMC1 opcode the firmware
itself ships and the vendor Toolbox itself sends. The duplex unlock uses
Zebra's own secure-action verbs through the verifier's designed interface —
no exploit, no malformed-input primitive, no destructive opcode is offered.
For ownership/authorization terms see README.md "Disclaimer & scope".

Read-only operations fire freely. Everything that changes printer state
(secure actions, key/passkey writes, capability/config/device-control writes)
requires the explicit `--yes` flag and is followed by a read-back in the same run.

Protocol: see PROTOCOL.md. Usage: see README.md.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import re
import socket
import struct
import sys
import time
from datetime import datetime

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "error: the 'cryptography' package is required  (pip install cryptography)\n")
    raise SystemExit(2)

# ---------------------------------------------------------------- constants

MAGIC = b"ZMC1"
REQ_HDR = 16            # request header length; payload at +0x10
REP_HDR = 32            # reply header length; payload at +0x20
AES_TAIL = "2b7e151628aed2a6"       # fixed tail appended to the shared secret
DH_PRIME = 2 ** 61 - 1               # host-supplied modulus; the unit accepts it
DH_BASE = 2

# Lab default was a live unit; published defaults are placeholders.
# --host uses RFC 5737 documentation space, so a bare run cannot hit anyone.
DEFAULT_HOST = "192.0.2.1"
DEFAULT_PORT = 9100
DEFAULT_WEB_PORT = 80
DEFAULT_WEB_AUTH = None              # pass your own with --web-auth; XML URIs need none
DEFAULT_MODEL = "ZXP Series 7"
DEFAULT_SERIAL = "123456789"         # example — set --serial to your unit's number
DEFAULT_PACE = 12.0                  # seconds between device contacts (lab policy)
BIG_OUTBUF = 0x8800                  # >= this needed for C1/00 and AE/03 replies
XML_HDR = '<?xml version="1.0" encoding="UTF-8" ?>\n'

# Opcode table (verified live against a ZXP7, FW FZ7MG.03.08.00).
# +0x05 of the request is the sub-command for dispatch-coded commands and the
# "payload is encrypted" flag for 0xB0/0xBD.
OPCODES = {
    0xA0: ("start_action",        "write"),
    0xA1: ("write_data",          "write"),
    0xA2: ("end_action",          "write"),
    0xA3: ("cancel_action",       "write"),
    0xA4: ("device_control",      "write"),
    0xA5: ("get_capabilities",    "read"),
    0xA6: ("get_configuration",   "read"),
    0xA7: ("set_configuration",   "write"),
    0xA8: ("get_status",          "read"),
    0xAA: ("get_log_history",     "read"),
    0xAB: ("get_printer_id",      "read"),
    0xAC: ("reset_printer",       "forbidden"),
    0xAE: ("nvm_backup",          "mixed"),
    0xB0: ("set_secure_action",   "write"),
    0xB1: ("get_secure_action",   "read"),
    0xB8: ("set_capabilities",    "write"),
    0xBC: ("diffie_hellman",      "session"),
    0xBD: ("get_nonce",           "read"),
    0xBE: ("get_displayed_msg",   "read"),
    0xC0: ("get_cal_lut",         "read"),
    0xC1: ("get_nvm",             "read"),
    0xC2: ("restore_nvm",         "undispatched"),
}

# Secure-action verbs (firmware verb table, 25 entries).
VERBS = [
    "cancel_printer_passkey", "reset_printer_serial_number", "reset_physical_address",
    "clear_error_log", "clear_card_cleaning_log", "clear_service_log", "reset_card_count",
    "reset_impression_count", "reset_system_defaults", "reset_oem", "reset_media_auth_cfg",
    "set_single_sided", "set_double_sided", "reset_laminator_serial_number",
    "reset_cards_laminated", "lock_printer", "unlock_printer", "unlock_eeprom",
    "clear_i2c_error_stats", "uhf_connect", "uhf_disconnect", "set_teeth16_installed",
    "clear_teeth16_installed", "set_stacker_installed", "clear_stacker_installed",
]

# Frames that perform destructive backup-plane writes. Withheld from the
# documentation and refused outright — not offered even with --yes.
FORBIDDEN_FRAMES = {(0xAE, 0x01), (0xAE, 0x02)}

SE_MEANING = {
    0:     "success",
    2:     "XML syntax error",
    3:     "XML parse error: no element found",
    4:     "XML parse error: not well-formed / invalid token",
    7:     "XML parse error: mismatched tag",
    9:     "XML parse error: junk after document element",
    3003:  "unknown primary opcode",
    3004:  "illegal sub-command (e.g. GetCalLut type)",
    3009:  "XML too big for the advertised output buffer",
    3021:  "expat parse failure on the plaintext path",
    3022:  "no job (idle printer) on get_job_status",
    16001: "invalid passkey — access denied",
    16002: "crypto key not set — session required",
    16004: "encrypted request refused (no session, or empty payload)",
    16005: "HMAC mismatch, or invalid tag sequence/formatting",
    16006: "secure action refused — verb name not delivered to the dispatcher",
}

FLAGBITS = {0x10: "PASSKEY active", 0x20: "alarm present (not a security bit)",
            0x40: "HOST_AUTH active", 0x80: "ENCRYPTION active"}

# HTTP URIs proven safe to GET (read-only, no side effects). This is an
# allow-list: other web endpoints are fragile and intentionally undocumented —
# never fetch anything outside this list.
SAFE_XML = ["PrinterId.xml", "Capabilities.xml", "Status.xml", "ZmcHeader.xml",
            "Display.xml", "FreeRam.xml", "FreeFlash.xml", "Media.xml",
            "AllMedia.xml", "JobList.xml", "ErrorLog.xml", "ServiceLog.xml",
            "EventLog.xml", "CleaningLog.xml", "NetDiag.xml"]

# ---------------------------------------------------------------- pacer

_last_contact = 0.0


def pace(min_interval: float) -> None:
    """Enforce >= min_interval seconds between contacts with the printer."""
    global _last_contact
    wait = _last_contact + min_interval - time.time()
    if wait > 0:
        time.sleep(wait)
    _last_contact = time.time()


# ---------------------------------------------------------------- framing

def build_request(primary: int, sub: int = 0, payload: bytes = b"",
                  outbuf: int = 0x10400) -> bytes:
    """16-byte ZMC1 request header + payload.

    +0x00 'ZMC1' | +0x04 primary | +0x05 sub / encrypted-flag | +0x06 0 | +0x07 0
    | +0x08 u32 output-buffer size offered | +0x0c u32 payload length | payload.
    """
    return (MAGIC + bytes([primary & 0xFF, sub & 0xFF, 0, 0])
            + struct.pack("<I", outbuf) + struct.pack("<I", len(payload)) + payload)


def parse_reply(buf: bytes, sent_primary: int = None, sent_sub: int = None) -> dict:
    """Parse the 32-byte reply header. A reply that duplicates the previous
    reply byte-for-byte, or echoes a different command word than we sent,
    means the command dispatched no reply of its own (global reply buffer)."""
    out = {"bytes": len(buf), "raw": buf}
    if len(buf) < REP_HDR:
        out["se"] = None
        out["note"] = "short reply (firmware emitted fewer than 32 bytes)"
        return out
    cmd_word = struct.unpack_from("<H", buf, 0x04)[0]
    out["echo_cmd"] = cmd_word
    out["fl"] = buf[0x0C]
    out["se"] = struct.unpack_from("<H", buf, 0x0D)[0]
    out["so"] = struct.unpack_from("<H", buf, 0x16)[0]
    out["rl"] = struct.unpack_from("<I", buf, 0x1C)[0]
    out["payload"] = buf[REP_HDR:REP_HDR + out["rl"]]
    if sent_primary is not None:
        want = (sent_primary & 0xFF) | ((sent_sub & 0xFF) << 8)
        if cmd_word != want:
            out["note"] = ("reply echoes command 0x%04x, not the 0x%04x sent — the "
                           "command produced no reply of its own (replayed reply buffer)"
                           % (cmd_word, want))
    return out


class ZMCConn:
    """One TCP connection to port 9100. The unit expects one request/response
    exchange per connection; multi-step sessions (DH -> nonce -> B1 -> B0)
    keep ONE socket open for all frames."""

    def __init__(self, host: str, port: int, min_pace: float, timeout: float = 40.0):
        self.host, self.port = host, port
        self.min_pace = min_pace
        self.timeout = timeout
        self.sock = None

    def __enter__(self):
        pace(self.min_pace)
        self.sock = socket.create_connection((self.host, self.port), timeout=10)
        self.sock.settimeout(self.timeout)
        return self

    def __exit__(self, *exc):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        return False

    def call(self, primary: int, sub: int = 0, payload: bytes = b"",
             outbuf: int = 0x10400, save_dir: str = None, tag: str = None) -> dict:
        self.sock.sendall(build_request(primary, sub, payload, outbuf))
        buf = b""
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) >= REP_HDR:
                    rl = struct.unpack_from("<I", buf, 0x1C)[0]
                    if len(buf) >= REP_HDR + rl:
                        break
        except socket.timeout:
            pass
        rep = parse_reply(buf, primary, sub)
        name = tag or f"{primary:02x}_{sub:02x}"
        if save_dir:
            raw_path = os.path.join(save_dir, name + ".bin")
            with open(raw_path, "wb") as fh:
                fh.write(buf)
            rep["saved"] = raw_path
        op = OPCODES.get(primary, ("unknown", "unknown"))
        rep["cmd"] = f"{primary:02x}/{sub:02x} {op[0]}"
        rep["se_meaning"] = SE_MEANING.get(rep.get("se"), "")
        return rep


# ---------------------------------------------------------------- crypto

def aes_encrypt(key: bytes, plaintext: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    """Wire envelope: IV (16 bytes) || AES-128-CBC(plaintext, PKCS#7)."""
    pad = 16 - (len(plaintext) % 16)
    ct = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + ct.update(plaintext + bytes([pad]) * pad)


def aes_decrypt(key: bytes, envelope: bytes) -> bytes:
    """Strip the leading IV, decrypt CBC, strip PKCS#7."""
    if len(envelope) < 32 or (len(envelope) - 16) % 16:
        raise ValueError("payload is not IV || CBC blocks")
    pt = Cipher(algorithms.AES(key), modes.CBC(envelope[:16])).decryptor().update(envelope[16:])
    n = pt[-1]
    return pt[:-n] if 1 <= n <= 16 else pt


def credential_digest(model: str, serial: int, nonce: int, key: bytes) -> str:
    """The accepted secure-action credential, verified live 2026-11-23:
    HMAC-SHA1(key, model[12] || serial u32LE || nonce u32LE), 40 lowercase hex.
    key = the unit's host_authentication_key (16 raw bytes)."""
    msg = model.encode()[:12].ljust(12, b"\x00") + struct.pack("<II", serial, nonce)
    return hmac_mod.new(key, msg, hashlib.sha1).hexdigest()


# ---------------------------------------------------------------- documents

def directive_document(model: str, serial_str: str, verb: str, nonce: int, key: bytes) -> str:
    """The accepted directive spelling: the verb is the ELEMENT TEXT of a <name>
    child of <action>. The vendor Save-Request spelling <action name="..."/> is
    NOT what the wire takes (it answers se=16006)."""
    return (XML_HDR + f"<keys><action><name>{verb}</name>"
            + f'<printer model="{model}" serial="{serial_str}" nonce="0x{nonce:x}">'
            + f"<hmac>{credential_digest(model, int(serial_str), nonce, key)}</hmac>"
            + "</printer></action></keys>")


def keys_set_document(fields: list) -> str:
    """User-XML key/passkey write document: <keys><set>current/new pairs</set></keys>."""
    body = "".join(f"<{name}>{value}</{name}>" for name, value in fields)
    return XML_HDR + "<keys><set>" + body + "</set></keys>"


def passkey_exchange_document(passkey_hex: str) -> str:
    return XML_HDR + f"<xml><passkey>{passkey_hex}</passkey></xml>"


def dh_request(priv: int = 1) -> tuple:
    """DH request body. priv=1 (host_interim_key = base) => shared secret equals
    the printer_interim_key: no discrete log needed. Returns (body_bytes, priv)."""
    host_pub = pow(DH_BASE, priv, DH_PRIME)
    body = (XML_HDR + "<diffie_hellman>"
            + f"<base>{DH_BASE}</base><modulus>{DH_PRIME}</modulus>"
            + f"<host_interim_key>{host_pub}</host_interim_key></diffie_hellman>").encode()
    return body, priv


def session_key_from_reply(text: str, priv: int) -> bytes:
    m = re.search(r"<printer_interim_key>\s*(0x[0-9a-fA-F]+|\d+)\s*</printer_interim_key>", text)
    if not m:
        raise ValueError("no <printer_interim_key> in the DH reply")
    printer_pub = int(m.group(1), 0)
    shared = pow(printer_pub, priv, DH_PRIME) & 0xFFFFFFFFFFFFFFFF
    return bytes.fromhex(f"{shared:016x}{AES_TAIL}")


def get_nonce(reply: dict) -> int:
    m = re.search(r"0x([0-9a-fA-F]+)", reply.get("payload", b"").decode("latin1", "replace"))
    if not m:
        raise ValueError("no nonce in the 0xBD/01 reply")
    return int(m.group(1), 16)


# ---------------------------------------------------------------- HTTP plane

def http_get(host: str, port: int, path: str, auth: str = None, timeout: float = 15.0) -> str:
    headers = f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
    if auth:
        headers += "Authorization: Basic " + base64.b64encode(auth.encode()).decode() + "\r\n"
    headers += "\r\n"
    pace(DEFAULT_PACE)
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(headers.encode())
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        s.close()
        return buf.decode("latin1", "replace")
    except Exception as exc:  # noqa: BLE001
        return f"ERR {exc}"


def http_post(host: str, port: int, path: str, data: str, auth: str, timeout: float = 15.0) -> str:
    pace(DEFAULT_PACE)
    body = data.encode()
    headers = (f"POST {path} HTTP/1.0\r\nHost: {host}\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\n")
    if auth:
        headers += "Authorization: Basic " + base64.b64encode(auth.encode()).decode() + "\r\n"
    headers += "\r\n"
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(headers.encode() + body)
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        s.close()
        return buf.decode("latin1", "replace")
    except Exception as exc:  # noqa: BLE001
        return f"ERR {exc}"


def xml_fields(text: str, want: tuple = None) -> dict:
    out = {}
    for k, v in re.findall(r"<(\w+)>([^<]*)</\1>", text):
        if want is None or k in want:
            if k not in out:
                out[k] = v
    return out


READBACK_FIELDS = ("print_type", "eeprom_locked", "firmware_version", "printer_serial",
                   "printer_state", "error", "ZmcFlagbits", "has_duplex")


def readback(args) -> dict:
    """Cheap HTTP state read-back: PrinterId + Capabilities + Status + ZmcHeader.
    These URIs are the proven-safe allow-list; Config.xml is excluded (it is
    not stable between reads) and nothing outside the allow-list is fetched."""
    out = {}
    for path in ("/PrinterId.xml", "/Capabilities.xml", "/Status.xml", "/ZmcHeader.xml"):
        out.update(xml_fields(http_get(args.host, args.web_port, path, args.web_auth),
                              READBACK_FIELDS))
    return out


# ---------------------------------------------------------------- sessions

def open_dh_session(conn: ZMCConn, save_dir: str, priv: int = 1):
    """Run the 0xBC/00 handshake on an already-open connection."""
    body, priv = dh_request(priv)
    r = conn.call(0xBC, 0, body, 0x400, save_dir=save_dir, tag="bc_dh")
    text = r.get("payload", b"").decode("latin1", "replace")
    if r.get("se") != 0:
        raise RuntimeError(f"DH handshake failed: se={r.get('se')} ({SE_MEANING.get(r.get('se'), '')})")
    return session_key_from_reply(text, priv), r


def syslog_verdicts(log_path: str, since_lines: int, pattern: str) -> list:
    if not log_path or not os.path.exists(log_path):
        return []
    lines = open(log_path, encoding="utf-8", errors="replace").read().splitlines()
    tail = lines[since_lines:]
    return [l.strip() for l in tail if re.search(pattern, l)][-14:]


SYSLOG_PAT = (r"SecureAction|RandomDigestValid|NOT valid|Access denied|flagbits|passkey"
              r"|tag sequence|duplex|HMAC|lock|Parse|error|done ok|length in=")


def log_mark(path: str) -> int:
    if not path or not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        return sum(1 for _ in fh)


def classify(reply: dict, syslog_tail: list) -> str:
    joined = " ".join(syslog_tail)
    if "invalid tag sequence" in joined:
        return "grammar rejected before the digest (se=16005)"
    if "HMAC match error" in joined:
        return "digest compared and failed — wrong key or message (se=16005)"
    if "not found" in joined:
        return "nonce missing or already consumed (one-time use)"
    if reply.get("se") == 0:
        return "ACCEPTED"
    if reply.get("se") == 16006:
        return "refused after the credential passed — verb not dispatched (se=16006)"
    return SE_MEANING.get(reply.get("se"), "other")


# ---------------------------------------------------------------- subcommands

def save_text(save_dir: str, name: str, text: str, secret: bool = False) -> str:
    path = os.path.join(save_dir, name)
    with open(path, "w") as fh:
        fh.write(text)
    if secret:
        os.chmod(path, 0o600)
    return path


def cmd_read(args, primary: int, sub: int = 0, payload: bytes = b"", outbuf: int = 0x10400,
             tag: str = None, secret: bool = False):
    """One read-only frame on its own connection, raw + decoded text saved."""
    if args.dry_run:
        print(f"[dry-run] would send: {primary:02x}/{sub:02x} "
              f"outbuf={outbuf:#x} payload={payload[:60]!r}")
        return None
    with ZMCConn(args.host, args.port, args.pace) as conn:
        rep = conn.call(primary, sub, payload, outbuf, save_dir=args.save_dir, tag=tag)
    text = rep.get("payload", b"").decode("latin1", "replace")
    if text.strip():
        path = save_text(args.save_dir, (tag or f"{primary:02x}_{sub:02x}") + ".xml", text, secret)
        print(f"{rep['cmd']}: se={rep['se']} ({rep['se_meaning']}) rl={rep.get('rl')} "
              f"fl=0x{rep.get('fl', 0):02x} so={rep.get('so')} -> {path}")
    else:
        print(f"{rep['cmd']}: se={rep['se']} ({rep['se_meaning']}) rl={rep.get('rl')} "
              f"fl=0x{rep.get('fl', 0):02x} so={rep.get('so')}")
    if rep.get("note"):
        print(f"  note: {rep['note']}")
    return rep


def cmd_health(args):
    if args.dry_run:
        print("[dry-run] would send: A8/00 ping, AB/00 id, then GETs of "
              "PrinterId/Capabilities/Status/ZmcHeader.xml (all read-only)")
        return
    print("— ZMC A8/00 ping —")
    cmd_read(args, 0xA8, 0x00, b"", 0x400, tag="a8_00")
    print("— ZMC AB/00 printer id —")
    cmd_read(args, 0xAB, 0x00, b"", 0x400, tag="ab_00")
    print("— HTTP state —")
    for k, v in readback(args).items():
        print(f"  {k}: {v}")


def cmd_capabilities(args):
    cmd_read(args, 0xA5, 0x00, b"<capabilities/>", 0x10400, tag="a5_00_caps")
    if args.media:
        cmd_read(args, 0xA5, 0x01, b"", 0x10400, tag="a5_01_media")


def cmd_config(args):
    cmd_read(args, 0xA6, 0x00, b"<configuration/>", BIG_OUTBUF, tag="a6_00_config")


def cmd_status(args):
    subs = args.subs.split(",") if args.subs else ["00", "03", "04", "05", "06", "07", "08", "0a", "0f"]
    for s in subs:
        cmd_read(args, 0xA8, int(s, 16), b"", 0x10400, tag=f"a8_{s}")


def cmd_logs(args):
    subs = args.subs.split(",") if args.subs else ["01", "04", "05", "06"]
    for s in subs:
        cmd_read(args, 0xAA, int(s, 16), b"", 0x10400, tag=f"aa_{s}")


def cmd_display(args):
    cmd_read(args, 0xBE, 0x00, b"", 0x400, tag="be_00_display")


def cmd_lut(args):
    types = args.types.split(",") if args.types else ["01", "02", "03", "81", "82", "83"]
    for t in types:
        cmd_read(args, 0xC0, int(t, 16), b"", BIG_OUTBUF, tag=f"c0_{t}")


def cmd_nonce(args):
    rep = cmd_read(args, 0xBD, 0x01, b"", 0x400, tag="bd_01_nonce")
    if rep is None:
        return
    try:
        print(f"  nonce = {hex(get_nonce(rep))} (single-use: burns at the first verify attempt)")
    except ValueError:
        pass


def cmd_nvm(args):
    cmd_read(args, 0xC1, 0x00, b"", BIG_OUTBUF, tag="c1_00_nvm")
    print("  note: the 8 blocks are ciphertext that changes on every read — the firmware "
          "re-encrypts its RAM NVM cache with a fresh IV; the at-rest key is unknown.")


def cmd_backup(args):
    print("warning: AE/03 returns the printer's whole NVM backup as plaintext XML — "
          "keys included. The dump is saved mode 600. It reads the FLASH BACKUP COPY, "
          "not live NVM; on units where the backup plane was previously written it "
          "answers se=0 rl=0 — see PROTOCOL.md §5.")
    cmd_read(args, 0xAE, 0x03, b"", BIG_OUTBUF, tag="ae_03_backup", secret=True)


def cmd_keys(args):
    """0xBC DH handshake, then 0xB1 GetSecureAction — the key block in clear."""
    if args.dry_run:
        print("[dry-run] would run one session: 0xBC DH -> 0xB1 key read-back (read-only)")
        return
    with ZMCConn(args.host, args.port, args.pace) as conn:
        sess, dh = open_dh_session(conn, args.save_dir)
        ct = aes_encrypt(sess, passkey_exchange_document(args.passkey_value).encode())
        rep = conn.call(0xB1, 0, ct, 0x2800, save_dir=args.save_dir, tag="b1_keys")
    print(f"DH ok, session key derived; B1: se={rep['se']} ({rep['se_meaning']}) rl={rep.get('rl')}")
    payload = rep.get("payload", b"")
    if rep.get("se") == 0 and len(payload) > 32:
        try:
            text = aes_decrypt(sess, payload).decode("latin1", "replace")
        except (ValueError, UnicodeDecodeError) as exc:
            print(f"  decrypt failed: {exc}")
            return
        path = save_text(args.save_dir, "b1_keyblock.xml", text, secret=True)
        print(f"  key block (plaintext, mode 600) -> {path}")
        print("  " + text.replace("\n", "\n  "))


def secure_action_session(args, verb: str = None, keys_doc: str = None) -> dict:
    """One TCP session. Directive path (verb): DH -> BD nonce -> B1 passkey -> B0 flag5=1.
    Key/passkey path (keys_doc): DH -> B0 flag5=0 (user XML). Nonces burn at the
    first verify attempt, so the BD nonce and the B0 firing must be in the same
    session with nothing in between."""
    rec = {}
    mark = log_mark(args.syslog_log)
    with ZMCConn(args.host, args.port, args.pace) as conn:
        sess, dh = open_dh_session(conn, args.save_dir)
        rec["dh"] = {"se": dh["se"], "rl": dh.get("rl")}
        if verb is not None:
            r2 = conn.call(0xBD, 0x01, b"", 0x400, save_dir=args.save_dir, tag="bd_01_nonce")
            nonce = get_nonce(r2)
            rec["nonce"] = hex(nonce)
            r3 = conn.call(0xB1, 0, aes_encrypt(sess, passkey_exchange_document(args.passkey_value).encode()),
                           0x2800, save_dir=args.save_dir, tag="b1_passkey")
            rec["b1_se"] = r3["se"]          # 16001 (wrong/cleared passkey) is fine —
            rec["b1_note"] = ("the passkey exchange never authorized the directive; it only "
                              "primes the encrypted path (verified live)")
            doc = directive_document(args.model, args.serial, verb, nonce, args.auth_key)
            rec["verb"] = verb
            rec["digest"] = credential_digest(args.model, int(args.serial), nonce, args.auth_key)
            r4 = conn.call(0xB0, 0x01, aes_encrypt(sess, doc.encode()), 0x400,
                           save_dir=args.save_dir, tag="b0_directive")
            save_text(args.save_dir, "b0_directive.xml", doc, secret=True)
        else:
            r4 = conn.call(0xB0, 0, aes_encrypt(sess, keys_doc.encode()), 0x400,
                           save_dir=args.save_dir, tag="b0_keys")
            save_text(args.save_dir, "b0_keys.xml", keys_doc, secret=True)
        rec["reply"] = {k: v for k, v in r4.items() if k not in ("raw", "payload")}
    time.sleep(3)
    rec["syslog"] = syslog_verdicts(args.syslog_log, mark, SYSLOG_PAT)
    rec["verdict"] = classify(rec["reply"], rec["syslog"])
    return rec


def fire_write(args, what: str, session_fn) -> None:
    """Gate for state-changing operations: needs --yes, then read-back."""
    if args.dry_run:
        print(f"[dry-run] would fire: {what}")
        return
    if not args.yes:
        print(f"REFUSED: '{what}' changes printer state. Re-run with --yes "
              "(explicit approval). Nothing was sent.")
        return
    print(f"— firing: {what} —")
    rec = session_fn()
    print(json.dumps(rec, indent=1))
    with open(os.path.join(args.save_dir, f"action_{what}.json"), "w") as fh:
        json.dump(rec, fh, indent=1)
    print("— read-back —")
    for k, v in readback(args).items():
        print(f"  {k}: {v}")


def cmd_action(args):
    if args.verb not in VERBS:
        print(f"note: '{args.verb}' is not in the firmware verb table; it will "
              "be refused (se=16006). Known verbs: " + ", ".join(VERBS))
    fire_write(args, f"secure_action_{args.verb}",
               lambda: secure_action_session(args, verb=args.verb))


def cmd_duplex(args):
    verb = "set_double_sided" if args.state == "on" else "set_single_sided"
    fire_write(args, f"duplex_{args.state}",
               lambda: secure_action_session(args, verb=verb))


def cmd_setkeys(args):
    fields = []
    pairs = [("passkey", args.current_passkey, args.new_passkey),
             ("host_authentication_key", args.current_host_auth, args.new_host_auth),
             ("data_encryption_key", args.current_data_enc, args.new_data_enc),
             ("printer_lock_key", args.current_lock_key, args.new_lock_key)]
    for name, cur, new in pairs:
        if new is not None:
            fields.append((f"current_{name}", cur if cur is not None else "0" * 32))
            fields.append((f"new_{name}", new))
    if not fields:
        print("nothing to do: give at least one --new-* value (see --help)")
        return
    doc = keys_set_document(fields)
    print(doc)
    fire_write(args, "setkeys", lambda: secure_action_session(args, keys_doc=doc))


def cmd_device(args):
    body = _xml_body(args)
    fire_write(args, "device_control", lambda: _single_write(args, 0xA4, 0, body, "a4_device"))


def cmd_setcap(args):
    body = _xml_body(args)
    fire_write(args, "set_capabilities", lambda: _single_write(args, 0xB8, 0, body, "b8_setcap"))


def cmd_setconfig(args):
    body = _xml_body(args)
    fire_write(args, "set_configuration", lambda: _single_write(args, 0xA7, 0, body, "a7_setconfig"))


def _xml_body(args) -> bytes:
    if args.body:
        return args.body.encode()
    if args.body_file:
        return open(args.body_file).read().encode()
    sys.exit(f"give the XML document via --body or --body-file (see --help)")


def _single_write(args, primary, sub, body, tag):
    with ZMCConn(args.host, args.port, args.pace) as conn:
        rep = conn.call(primary, sub, body, 0x400, save_dir=args.save_dir, tag=tag)
    return {k: v for k, v in rep.items() if k not in ("raw", "payload")}


def cmd_syslog(args):
    if args.dry_run:
        print(f"[dry-run] would {'POST /syslog.cgi' if args.state in ('on', 'off') else 'listen for UDP datagrams'} "
              f"({args.state})")
        return
    if args.state in ("on", "off") and not args.web_auth:
        sys.exit("/syslog.cgi needs the unit's web credential: pass --web-auth USER:PASSWORD")
    if args.state == "on":
        if not args.listen_addr:
            sys.exit("syslog on needs --listen-addr <your-ip> (the UDP host the log should stream to)")
        r = http_post(args.host, args.web_port, "/syslog.cgi",
                      f"server={args.listen_addr}&Submit=Submit", args.web_auth)
        print(f"syslog -> {args.listen_addr}: {'200' in r and 'POST accepted' or r[:80]}")
        print("on/off indicator = UDP datagram arrival, not Config.xml <syslog_addr>")
    elif args.state == "off":
        r = http_post(args.host, args.web_port, "/syslog.cgi",
                      "server=0.0.0.0&Submit=Submit", args.web_auth)
        print(f"syslog -> 0.0.0.0 (off): {'200' in r and 'POST accepted' or r[:80]}")
    else:  # check: count datagrams for --listen seconds; arrival = ON
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.bind(("0.0.0.0", args.udp_port))
        end = time.time() + args.listen
        n = 0
        lines = []
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(2048)
                n += 1
                if len(lines) < 5:
                    lines.append(data.decode("latin1", "replace").strip())
            except socket.timeout:
                continue
        sock.close()
        print(f"{n} datagrams in {args.listen} s ({n / args.listen:.2f}/s) — "
              f"{'ON' if n else 'OFF'}")
        for l in lines:
            print("  " + l)


def cmd_raw(args):
    payload = open(args.payload_file, "rb").read() if args.payload_file else b""
    primary = int(args.cmd, 16)
    sub = int(args.sub, 16)
    if (primary, sub) in FORBIDDEN_FRAMES:
        print("REFUSED: destructive backup-plane write frame — not offered "
              "(see README 'Disclaimer & scope'). Nothing was sent.")
        return
    kind = OPCODES.get(primary, ("unknown", "unknown"))[1]
    if args.dry_run:
        print(f"[dry-run] would send {args.cmd}/{args.sub} ({OPCODES.get(primary, ('unknown', '?'))[0]}), "
              f"{len(payload)} bytes, outbuf={args.outbuf}")
        return
    if kind == "forbidden":
        print("REFUSED: this opcode is destructive (printer reset). Not offered.")
        return
    if kind in ("write", "mixed") and not args.yes:
        print(f"REFUSED: opcode {args.cmd} is classified '{kind}' (state-changing). "
              "Re-run with --yes. Nothing was sent.")
        return
    with ZMCConn(args.host, args.port, args.pace) as conn:
        rep = conn.call(primary, sub, payload,
                        int(args.outbuf, 0), save_dir=args.save_dir,
                        tag=f"raw_{args.cmd}_{args.sub}")
    print(json.dumps({k: v for k, v in rep.items() if k not in ("raw", "payload")}, indent=1))


# ---------------------------------------------------------------- main

def cmd_selftest(args):
    """Offline regression checks for the protocol model — sends nothing to any device.
    Uses synthetic demo values; the same checks were run against the recorded
    live firing before publication (values withheld here, see README.md)."""
    key = bytes.fromhex("00112233445566778899aabbccddeeff")   # demo key, not a real one
    serial, nonce = 123456789, 0xdeadbeef
    digest = credential_digest("ZXP Series 7", serial, nonce, key)
    assert digest == "3bd6b8df0d3c51d0fe7d0cf490fa0a58197275ad", "credential digest"
    msg = "ZXP Series 7".encode()[:12].ljust(12, b"\0") + struct.pack("<II", serial, nonce)
    assert msg.hex() == "5a585020536572696573203715cd5b07efbeadde", "20-byte message layout"
    ct = aes_encrypt(key, b"<keys/>")
    assert len(ct) == 32 and aes_decrypt(key, ct) == b"<keys/>", "IV || CBC || PKCS#7 envelope"
    req = build_request(0xB0, 0x01, b"AB", 0x400)
    assert req[:4] == MAGIC and req[4] == 0xB0 and req[5] == 1 and req[6] == 0 and req[7] == 0
    assert struct.unpack_from("<I", req, 8)[0] == 0x400, "outbuf slot"
    assert struct.unpack_from("<I", req, 12)[0] == 2 and req[16:] == b"AB", "length slot + payload"
    buf = (MAGIC + struct.pack("<H", 0x01b0) + b"\0" * 6 + bytes([0xF0])
           + struct.pack("<H", 0) + b"\0" * 7 + struct.pack("<H", 5001) + b"\0" * 4
           + struct.pack("<I", 0))
    rep = parse_reply(buf, 0xB0, 1)
    assert rep["se"] == 0 and rep["so"] == 5001 and rep["fl"] == 0xF0 and rep.get("note") is None
    rep2 = parse_reply(buf, 0xC2, 0)          # echo mismatch -> replay flag
    assert rep2.get("note") and "replayed" in rep2["note"]
    sk = session_key_from_reply("<printer_interim_key>0x0123456789abcdef</printer_interim_key>", 1)
    assert sk.hex() == "0123456789abcdef2b7e151628aed2a6", "DH priv=1 session key"
    doc = directive_document("ZXP Series 7", "123456789", "set_double_sided", nonce, key)
    assert "<action><name>set_double_sided</name>" in doc and digest in doc, "directive shape"
    print("selftest: 8/8 offline protocol-model checks PASS (nothing was sent)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="zmc_tool.py",
        description="Zebra ZXP Series 7 ZMC1 protocol client "
                    "(read-only ops fire freely; state-changing ops need --yes).",
        epilog="See PROTOCOL.md for the wire format and README.md for worked examples.")
    ap.add_argument("--host", default=DEFAULT_HOST, help=f"printer IP (default {DEFAULT_HOST})")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="ZMC TCP port (default 9100)")
    ap.add_argument("--web-port", type=int, default=DEFAULT_WEB_PORT)
    ap.add_argument("--web-auth", default=None,
                    help="basic auth USER:PASSWORD for the web plane (XML URIs need none; "
                         "/syslog.cgi does)")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--serial", default=DEFAULT_SERIAL,
                    help="printer serial number (goes into the HMAC message)")
    ap.add_argument("--auth-key", default=os.environ.get("ZXP7_HOST_AUTH_KEY"),
                    help="16-byte host_authentication_key as 32 hex (or env ZXP7_HOST_AUTH_KEY)")
    ap.add_argument("--passphrase", default=os.environ.get("ZXP7_PASSPHRASE"),
                    help="passkey passphrase; sent on 0xB1 as MD5(passphrase)")
    ap.add_argument("--out", default="captures", help="capture directory (default ./captures)")
    ap.add_argument("--pace", type=float, default=DEFAULT_PACE,
                    help="min seconds between device contacts (default 12)")
    ap.add_argument("--syslog-log", default=None,
                    help="path of a UDP syslog capture file for verdict classification")
    ap.add_argument("--yes", action="store_true",
                    help="explicit approval for state-changing operations")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would be sent; send nothing")

    sub = ap.add_subparsers(dest="cmd_name", required=True)

    sub.add_parser("selftest", help="offline protocol-model checks — sends nothing")
    sub.add_parser("health", help="ping + printer id + HTTP state summary (read-only)")
    p = sub.add_parser("capabilities", help="0xA5/00 capabilities (+ --media for A5/01 ribbon list)")
    p.add_argument("--media", action="store_true")
    sub.add_parser("config", help="0xA6/00 configuration dump (read-only)")
    p = sub.add_parser("status", help="0xA8 status sweep (subs 00 03 04 05 06 07 08 0A 0F)")
    p.add_argument("--subs", help="comma list, e.g. 00,06,07")
    p = sub.add_parser("logs", help="0xAA log history sweep (subs 01 04 05 06)")
    p.add_argument("--subs")
    sub.add_parser("display", help="0xBE/00 the OCP screen (read-only)")
    p = sub.add_parser("lut", help="0xC0 calibration LUTs (types 01-03 installed, 81-83 default)")
    p.add_argument("--types")
    sub.add_parser("nonce", help="0xBD/01 issue a nonce (read-only, single-use)")
    sub.add_parser("nvm", help="0xC1/00 NVM blob dump (ciphertext, changes per read)")
    sub.add_parser("backup", help="0xAE/03 plaintext NVM backup dump (contains keys; "
                                   "reads the flash backup copy)")
    sub.add_parser("keys", help="DH session + 0xB1 key block read-back in clear")
    p = sub.add_parser("action", help="0xB0 secure action directive (STATE-CHANGING)")
    p.add_argument("--verb", required=True, choices=None,
                   help=f"one of: {', '.join(VERBS)}")
    p = sub.add_parser("duplex", help="sugar: on = set_double_sided, off = set_single_sided "
                                      "(STATE-CHANGING)")
    p.add_argument("state", choices=["on", "off"])
    p = sub.add_parser("setkeys", help="0xB0 user-XML key/passkey write (STATE-CHANGING)")
    p.add_argument("--current-passkey"); p.add_argument("--new-passkey")
    p.add_argument("--current-host-auth"); p.add_argument("--new-host-auth")
    p.add_argument("--current-data-enc"); p.add_argument("--new-data-enc")
    p.add_argument("--current-lock-key"); p.add_argument("--new-lock-key")
    p = sub.add_parser("device", help="0xA4 device control XML (STATE-CHANGING)")
    p.add_argument("--body"); p.add_argument("--body-file")
    p = sub.add_parser("setcap", help="0xB8 set capabilities XML (STATE-CHANGING)")
    p.add_argument("--body"); p.add_argument("--body-file")
    p = sub.add_parser("setconfig", help="0xA7 set configuration XML (STATE-CHANGING)")
    p.add_argument("--body"); p.add_argument("--body-file")
    p = sub.add_parser("syslog", help="printer syslog service: on/off/check (safe, pre-approved)")
    p.add_argument("state", choices=["on", "off", "check"])
    p.add_argument("--listen-addr", default=None, help="your UDP listener IP (required for on)")
    p.add_argument("--udp-port", type=int, default=514)
    p.add_argument("--listen", type=float, default=16.0, help="seconds to count datagrams")
    p = sub.add_parser("raw", help="send any frame (opcodes classified write need --yes)")
    p.add_argument("--cmd", default="a5"); p.add_argument("--sub", default="00")
    p.add_argument("--payload-file"); p.add_argument("--outbuf", default="0x10400")

    return ap


def main():
    args = build_parser().parse_args()

    # passkey value sent on 0xB1: MD5 of the passphrase, or 32 zeros if none given.
    args.passkey_value = hashlib.md5(args.passphrase.encode()).hexdigest() if args.passphrase else "0" * 32

    # host_authentication_key for the credential: needed by directive firings.
    if args.auth_key:
        try:
            args.auth_key = bytes.fromhex(args.auth_key)
            if len(args.auth_key) != 16:
                raise ValueError
        except ValueError:
            sys.exit("--auth-key must be exactly 32 hex characters (16 bytes)")

    needs_key = args.cmd_name in ("action", "duplex") and not args.dry_run
    if needs_key and args.auth_key is None:
        sys.exit("the secure-action credential needs the unit's host_authentication_key: "
                 "pass --auth-key HEX or set ZXP7_HOST_AUTH_KEY (see README.md)")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    args.save_dir = os.path.join(args.out, f"{args.cmd_name}_{stamp}")
    if not args.dry_run and args.cmd_name != "selftest":
        os.makedirs(args.save_dir, exist_ok=True)

    # Preview the directive document for action/duplex dry-runs (no device).
    if args.dry_run and args.cmd_name in ("action", "duplex"):
        verb = args.verb if args.cmd_name == "action" else (
            "set_double_sided" if args.state == "on" else "set_single_sided")
        if args.auth_key:
            print(directive_document(args.model, args.serial, verb, 0, args.auth_key))
            print("# nonce/digest above are for nonce 0 — the real ones are built from "
                  "the unit's 0xBD/01 reply at firing time")
        else:
            print(f"# would fire verb '{verb}' — the credential needs --auth-key "
                  "(or env ZXP7_HOST_AUTH_KEY); shape shown in PROTOCOL.md")
        return

    dispatch = {
        "health": cmd_health, "capabilities": cmd_capabilities, "config": cmd_config,
        "status": cmd_status, "logs": cmd_logs, "display": cmd_display, "lut": cmd_lut,
        "nonce": cmd_nonce, "nvm": cmd_nvm, "backup": cmd_backup, "keys": cmd_keys,
        "action": cmd_action, "duplex": cmd_duplex, "setkeys": cmd_setkeys,
        "device": cmd_device, "setcap": cmd_setcap, "setconfig": cmd_setconfig,
        "syslog": cmd_syslog, "raw": cmd_raw, "selftest": cmd_selftest,
    }
    try:
        dispatch[args.cmd_name](args)
    except OSError as exc:
        print(f"device contact failed: {exc}")
        print("If the unit is unreachable (no ping, connection refused, 'No route to host'), "
              "it is powered off or its network plane died — power-cycle it and wait a few "
              "minutes before retrying; do not keep probing.")
        sys.exit(1)


if __name__ == "__main__":
    main()
