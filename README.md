# ZXP7 ZMC1 — protocol research and host tool

A self-contained write-up of the **ZMC1 control protocol** of the Zebra ZXP
Series 7 card printer, plus `zmc_tool.py` — a single-file Python client that
runs every useful operation we recovered from the protocol, including the
**secure-action flow that enables duplex (2-sided) printing** on a unit whose
NVM reports `eeprom_locked yes`.

This folder is publishable: it contains **no device serials, no IPs, no
credentials, no keys**. Worked examples use synthetic demo values
(`zmc_tool.py selftest` checks the model against them). All claims are
verified live against a lab unit whose identifying values are deliberately
withheld from this repository.

---

## Table of contents

* [What was found](#what-was-found)
* [Requirements](#requirements)
* [Install](#install)
* [Quick start — enable duplex](#quick-start--enable-duplex)
* [Configuration](#configuration)
* [Command reference](#command-reference)
* [How the tool protects the printer](#how-the-tool-protects-the-printer)
* [Interpreting answers](#interpreting-answers)
* [Keys and secrets](#keys-and-secrets)
* [Verification status](#verification-status)
* [Troubleshooting](#troubleshooting)
* [Repository layout](#repository-layout)
* [Disclaimer & scope](#disclaimer--scope)
* [Acknowledgements](#acknowledgements)

---

## What was found

On a ZXP Series 7 card printer (FW `FZ7MG.03.08.00`, TCP `9100`):

1. **A large unauthenticated read surface.** Capabilities, configuration, status
   subs, logs, printer ID, the OCP display, calibration LUTs, the NVM blob and
   even the printer's whole NVM backup as plaintext XML answer on port 9100
   with no credential at all.
2. **The secure-action credential is reproducible.** `0xB0 SET_SECURE_ACTION`
   accepts `HMAC-SHA1(host_authentication_key, model[12] ‖ serial u32LE ‖
   nonce u32LE)` as 40 hex — a 20-byte message, keyed with the unit's
   `host_authentication_key`, *not* the 56-byte vendor message and not the
   factory key literal.
3. **The verb spelling the parser dispatches on** is the **element text of a
   `<name>` child of `<action>`** — the vendor Toolbox's own Save-Request
   spelling `<action name="..."/>` is not the wire spelling and answers
   `se=16006`.
4. **Duplex unlock:** firing `set_double_sided` with that credential returns
   `se=0` and `Capabilities.xml` flips `print_type 1_side → 2_side`. The change
   **survives a power cycle**. `set_single_sided` reverses it.

Details, byte-level layout and flow charts: [PROTOCOL.md](PROTOCOL.md).

---

## Requirements

* Python **3.8+**
* [`cryptography`](https://pypi.org/project/cryptography/) — AES-128-CBC for the
  session envelope:

```bash
pip install cryptography
```

Nothing else. The tool is one file; no build step.

---

## Quick start — enable duplex

You need the unit's `host_authentication_key` (16 bytes, 32 hex) — the key the
verifier's digest is keyed on. See [Keys and secrets](#keys-and-secrets).

```bash
# 0. offline model check — runs on any machine, sends nothing
python3 zmc_tool.py selftest

# 1. see the current state of your unit
python3 zmc_tool.py --host <printer-ip> --serial <your-serial> health

# 2. preview the exact directive without sending anything
ZXP7_HOST_AUTH_KEY=<32-hex> \
  python3 zmc_tool.py --host <printer-ip> --serial <your-serial> --dry-run duplex on

# 3. fire it (state-changing — needs --yes; the tool read-backs after)
ZXP7_HOST_AUTH_KEY=<32-hex> \
  python3 zmc_tool.py --host <printer-ip> --serial <your-serial> --yes duplex on

# expected: verdict ACCEPTED, and the read-back shows print_type: 2_side
```

Reverse it with `--yes duplex off`.

The full session the tool runs for step 3 is
`0xBC DH → 0xBD nonce → 0xB1 passkey → 0xB0 directive` **on one TCP
connection** — this exact order is required (see PROTOCOL.md §6–§8).

Before any secure-action firing, it is worth pointing the printer's syslog
service at your host — the firmware's verdict lines tell a wrong message apart
from a wrong key:

```bash
# start a UDP listener on your machine first (any sniffer works; port 514),
# then arm the oracle:
python3 zmc_tool.py --host <printer-ip> --web-auth <user:password> \
  syslog on --listen-addr <your-ip>
python3 zmc_tool.py --host <printer-ip> --syslog-log syslog_capture.log --yes duplex on
python3 zmc_tool.py --host <printer-ip> --web-auth <user:password> syslog off
```

---

## Configuration

Global options go **before** the subcommand:

| Option | Default | Meaning |
|---|---|---|
| `--host` | `192.0.2.1` | printer IP — documentation range, replace with yours |
| `--port` | `9100` | ZMC TCP port |
| `--web-port` | `80` | web/CGI plane |
| `--web-auth` | none | `USER:PASSWORD` for the web plane (XML URIs need none; `/syslog.cgi` does) |
| `--model` | `ZXP Series 7` | model string in the MAC message |
| `--serial` | `123456789` | example serial — set it to your unit's number |
| `--auth-key` / env `ZXP7_HOST_AUTH_KEY` | — | 16-byte host-auth key, 32 hex |
| `--passphrase` / env `ZXP7_PASSPHRASE` | — | passkey passphrase (sent on `0xB1` as MD5) |
| `--out` | `captures/` | capture directory |
| `--pace` | `12` | min seconds between device contacts |
| `--syslog-log` | — | UDP syslog capture file, for verdict classification |
| `--yes` | off | explicit approval for state-changing operations |
| `--dry-run` | off | print what would be sent, send nothing |

The unit paces replies at ~10–17 s and slows further if hammered — keep
`--pace` at 12 or above.

---

## Command reference

Classification: **read** = no printer state changes; **session** = sets up an
ephemeral crypto session (per connection, nothing persisted); **write** = needs
`--yes`, read-back follows automatically.

| Command | Class | What it does |
|---|---|---|
| `selftest` | offline | protocol-model regression checks (framing, envelope, credential, directive shape) — sends nothing |
| `health` | read | `A8/00` ping, `AB/00` printer id, HTTP state summary |
| `capabilities [--media]` | read | `A5/00` capabilities XML; `--media` adds `A5/01` ribbon list |
| `config` | read | `A6/00` full configuration (~8.5 KB) |
| `status [--subs …]` | read | `A8` sweep: ping, job list, free RAM, free flash, media, sensors, counts, general status, i2c stats |
| `logs [--subs …]` | read | `AA` error/cleaning/service/event history |
| `display` | read | `BE/00` the operator-panel screen |
| `lut [--types …]` | read | `C0` calibration tables: `01–03` installed, `81–83` factory defaults |
| `nonce` | read | `BD/01` issue a single-use nonce |
| `nvm` | read | `C1/00` NVM blob (8 blocks, ciphertext, fresh IV per read) |
| `backup` | read* | `AE/03` full NVM backup as **plaintext XML** (keys included — dump is saved mode `600`). *Reads the flash backup copy, not live NVM; see PROTOCOL.md §5 |
| `keys` | read | `0xBC` DH session + `0xB1` key block read-back in clear |
| `action --verb V` | **write** | `0xB0` secure action directive, any of the 25 firmware verbs |
| `duplex on\|off` | **write** | sugar for `--verb=set_double_sided` / `set_single_sided` |
| `setkeys --new-* …` | **write** | `0xB0` user-XML passkey / host-auth / data-enc / lock-key write (`<keys><set>`) |
| `device --body …` | **write** | `A4` device-control XML (rfid/radio/contactless grammar) |
| `setcap --body …` | **write** | `B8` set-capabilities XML (printer-type elements are lock-gated) |
| `setconfig --body …` | **write** | `A7` set-configuration XML |
| `syslog on\|off\|check` | safe | redirect the firmware debug log to your UDP listener / check arrival rate |
| `raw --cmd … --sub …` | mixed | send any frame; opcodes classified write need `--yes`; destructive backup-plane write frames are refused outright |

Deliberately **not implemented**: `0xAC RESET_PRINTER` (destructive), firmware
download, backup-plane write operations, and any fragile web-plane endpoint.
The audit surfaced a handful of weaknesses that can reset, crash or alter the
unit; their identities and trigger details are **withheld from this
publication** (held for responsible disclosure to Zebra), and the tool never
requests or sends anything outside its proven-safe allow-list.


---

## How the tool protects the printer

* **Pacing:** ≥ 12 s (configurable) between any two contacts with the unit —
  ZMC frames and HTTP requests alike. Multi-frame sessions (`DH → nonce → B1 →
  B0`) use one connection, so they don't double-count.
* **One connection per operation**, as the firmware expects.
* **Write gate:** state-changing subcommands refuse without `--yes` and say so
  before sending anything.
* **Read-back in the same run:** every write ends with fresh
  `PrinterId.xml` / `Capabilities.xml` / `Status.xml` / `ZmcHeader.xml` fields
  (`print_type`, `eeprom_locked`, `ZmcFlagbits`, …).
* **Unsafe URIs are never touched:** HTTP reads use a fixed allow-list of
  proven-safe XML URIs (`PrinterId`, `Capabilities`, `Status`, `ZmcHeader`, …).
  The audit identified a few web-plane endpoints that can reset or otherwise
  affect the unit; their identities and trigger details are deliberately **not
  published here** — treat every endpoint outside the allow-list as
  off-limits. `Config.xml` is excluded from read-backs because it is not
  byte-stable between reads.
* **Replay-aware:** a reply header that echoes another command (or duplicates
  the previous reply byte-for-byte) is flagged — the firmware re-sends its
  global reply buffer when a command dispatches nothing.

---

## Interpreting answers

| `se` | Meaning |
|---|---|
| `0` | success |
| `2/3/4/7/9` | expat XML parse errors |
| `3003` | unknown primary opcode (e.g. command bytes swapped) |
| `3004` | illegal sub-command |
| `3009` | XML too big for the advertised output buffer |
| `3022` | no job (idle printer) |
| `16001` | invalid passkey — access denied |
| `16002` | crypto key not set — needs a session first |
| `16004` | encrypted request refused (no session, or empty payload) |
| `16005` | HMAC mismatch **or** invalid tag sequence/formatting |
| `16006` | credential passed but verb not dispatched — wrong verb position |

With the syslog oracle armed (`syslog on` + `--syslog-log`), the tool
classifies firings as *grammar rejected / digest compared and failed / nonce
consumed / ACCEPTED / refused-after-credential*. The verdict lines are the
only way to separate "wrong message" from "wrong key" — see PROTOCOL.md §9.

---

## Keys and secrets

The directive's MAC is keyed with the unit's **`host_authentication_key`**
(16 bytes). How you get one:

* On a **unit you control**, install your own key via
  `setkeys --new-host-auth <32-hex>` (this is what we did — the factory
  verifier key literal is *not* accepted on this build; PROTOCOL.md §8).
* The key lives in the unit's encrypted key block; `keys` (DH + `0xB1`) reads
  the current values back in clear.

Never commit keys: pass them via `--auth-key` / `ZXP7_HOST_AUTH_KEY`, and keep
captures out of git (`.gitignore` covers `captures/`). The `backup` dump
contains the printer's plaintext secrets — mode `600`, do not publish.

---

## Verification status

The protocol model here was verified live against one lab unit
(FW `FZ7MG.03.08.00`, sessions 2026-10-24 → 2026-11-23): the read opcodes'
reply shapes/sizes are measured, the DH session-key derivation decrypts our
and the vendor's sessions, and the directive grammar + credential produced the
accepted firing (see PROTOCOL.md §8/§12). **The unit's identifying values —
serial, IPs, credentials, installed keys, and the real digests — are not in
this repository.**

What ships here instead:

* `python3 zmc_tool.py selftest` — deterministic offline checks of framing,
  the IV‖CBC‖PKCS#7 envelope, the 20-byte credential layout, the directive
  shape and the reply-buffer replay rule, all against synthetic demo values.
* Before publishing, `zmc_tool.py` was additionally validated offline against
  the recorded accepted firing byte-for-byte (digest, document, session key)
  using the lab values held outside this repo — that is what the selftest
  layout constants mirror.

---

## Troubleshooting

| Symptom | Cause / action |
|---|---|
| `Network is unreachable` / refused / no ping | printer is powered off, or its network plane died after a fault — power-cycle and wait a few minutes; do not keep probing |
| Replies slower than 17 s | you are hammering it: raise `--pace` |
| `se=3009` on an XML command | your output-buffer slot got the payload length (a classic framing bug): `+0x08` = buffer size, `+0x0c` = payload length — the tool does this correctly |
| `se=16005` + syslog `HMAC match error!` | wrong key or wrong message layout |
| `se=16005` + syslog `invalid tag sequence` | wrong document nesting |
| `se=16006` | credential passed, verb never reached the dispatcher — use the `<action><name>verb</name>` spelling |
| reply header echoes a different command | the command dispatched nothing (global reply buffer replay) |
| `AE/03` answers `se=0 rl=0` | the backup copy is unreadable on units where it was previously rewritten — treat the AE plane as spent there; never fire the AE write sub-commands (the tool refuses them) |
| `syslog check` shows 0 lines/s after you turned it on | a reboot resets the syslog destination — re-arm |

---

## Repository layout

```
zxp7-zmc-research/
├── README.md          this file
├── PROTOCOL.md        the ZMC1 protocol write-up + flow charts
├── zmc_tool.py        the client (single file)
└── captures/          created at runtime; git-ignored
```

## Disclaimer & scope

**This research uses only OEM-supplied command sets.** Every operation described
here and implemented in `zmc_tool.py` is a command Zebra's own firmware implements
and Zebra's own host software (the ZXP Series 7 Toolbox) sends: the ZMC1 opcodes
(`0xA5`…`0xC1`), the Diffie-Hellman session handshake, and the secure-action verbs
from the firmware's own verb table (`set_double_sided`, `set_single_sided`, …).
Duplex printing is gated by a capability bit, and the path described here reaches it
through the **secure-action interface Zebra designed and shipped** — a correctly
formatted, correctly keyed `0xB0` directive that the firmware's verifier accepts by
design. It is an OEM feature being satisfied, not a bug being exploited.

Specifically:

* **No exploitation of any weakness.** The audit surfaced security weaknesses
  in the web plane and the NVM-backup plane. None is used anywhere on the
  unlock path, and their identities and trigger details are deliberately
  **not republished here** — they are held for responsible disclosure to
  Zebra. The tool implements only read commands and Zebra's designed
  secure-action verbs; destructive or irreversible operations
  (`0xAC RESET_PRINTER`, firmware download, backup-plane write/apply frames,
  permanent locks) are refused outright.
* **No credential was extracted or defeated beyond its design.** The verifier
  compares an HMAC against a key slot in the unit; the value in that slot on our
  unit is one the **owner installed through Zebra's own key-write path**
  (`0xB0` user-XML `<keys><set>`). The plaintext key-disclosure surfaces
  (`AE/03`, `0xB1`) are reported as findings; in our workflow they only ever read
  back the keys we ourselves installed.
* **Everything performed is reversible.** `set_double_sided` is reversed by
  `set_single_sided`; key writes are re-writable; the passkey is clearable. No
  irreversible state change is produced by this tool.
* **Ownership and authorization.** This research was carried out on equipment
  owned by the authors. Using it against printers you do not own, or do not have
  explicit written authorization to test, is out of scope and not intended.
  Enabling a feature the hardware already contains on a printer you own and was 
  EoL'd by the OEM is deemed fit for public reseach.
* **Trademarks.** Zebra and ZXP Series 7 are trademarks of Zebra Technologies
  Inc. This is independent research, unaffiliated with and not endorsed by Zebra.
* **Disclosure intent.** The weaponizable weaknesses — fragile web-plane endpoints and
  backup-plane write primitives — are intentionally **not reproduced in this publication**.

---

## Acknowledgements

With thanks to the **Qwen Team**: This research was carried out with the help of open weight
Qwen models, which accelerated the project immensely — protocol
reverse-engineering, firmware analysis, probe tooling and the writing of this
documentation all moved far faster with them at hand.
