"""Simulated hardware-backed device attestation.

Real mobile platforms let an app ask the OS for a signed statement that
(a) the request comes from a genuine, unmodified device and (b) a key that
never leaves secure hardware signed a server-issued nonce.  Examples are
Google Play Integrity and Apple App Attest / DeviceCheck.

We cannot use those services in a classroom testbed, so this module
simulates the same trust relationship with HMAC:

* A "platform root" secret stands in for the vendor's attestation root.
* Every genuine phone has a per-hardware key derived from that root and its
  hardware serial.  The key is never exposed to app code.
* The token carries a stable, pseudonymous hardware id (hash of the serial)
  that survives app reinstalls -- analogous to Play Integrity "device recall".

Consequences that matter for the threat model:

* Emulators / headless scripts have no hardware key -> "missing" or "invalid".
* Copying (spoofing) another device_id without its hardware key -> "invalid".
* Rotating the app-level device_id on the SAME phone still yields the SAME
  hw_id, so rotation is visible as hw_id -> many device_ids fan-out.
* Rooted / custom-ROM phones still sign, but only at "basic" integrity -> "weak".
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional

_PLATFORM_ROOT = b"simulated-platform-attestation-root"


def _hw_key(hw_serial: str) -> bytes:
    return hmac.new(_PLATFORM_ROOT, hw_serial.encode(), hashlib.sha256).digest()


def hw_id_for(hw_serial: str) -> str:
    """Stable pseudonymous hardware identifier (survives reinstall/ID reset)."""
    return hashlib.sha256(b"hwid:" + hw_serial.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class AttestationToken:
    device_id: str
    hw_id: Optional[str]
    integrity: str          # "device" (full) or "basic" (rooted / modified OS)
    nonce: str
    sig: Optional[bytes]


def _payload(device_id: str, hw_id: Optional[str], integrity: str, nonce: str) -> bytes:
    return f"{device_id}|{hw_id}|{integrity}|{nonce}".encode()


def sign_genuine(device_id: str, hw_serial: str, nonce: str, rooted: bool = False) -> AttestationToken:
    hw_id = hw_id_for(hw_serial)
    integrity = "basic" if rooted else "device"
    sig = hmac.new(_hw_key(hw_serial), _payload(device_id, hw_id, integrity, nonce), hashlib.sha256).digest()
    return AttestationToken(device_id, hw_id, integrity, nonce, sig)


def forge(device_id: str, nonce: str, claimed_hw_id: Optional[str] = None) -> AttestationToken:
    """What an emulator / spoofer can produce without a hardware key."""
    fake_key = hashlib.sha256(b"attacker-guess" + device_id.encode()).digest()
    hw = claimed_hw_id or "0000000000000000"
    sig = hmac.new(fake_key, _payload(device_id, hw, "device", nonce), hashlib.sha256).digest()
    return AttestationToken(device_id, hw, "device", nonce, sig)


def verify(token: Optional[AttestationToken], expected_nonce: str, hw_serial_lookup) -> str:
    """Server-side verification.

    ``hw_serial_lookup(hw_id)`` models the platform vendor's verification
    service (in reality the server sends the token to Google/Apple, or checks
    a certificate chain).  Returns one of: ok, weak, invalid, missing.
    """
    if token is None or token.sig is None:
        return "missing"
    if token.nonce != expected_nonce:
        return "invalid"
    serial = hw_serial_lookup(token.hw_id) if token.hw_id else None
    if serial is None:
        return "invalid"
    good = hmac.new(_hw_key(serial), _payload(token.device_id, token.hw_id, token.integrity, token.nonce),
                    hashlib.sha256).digest()
    if not hmac.compare_digest(good, token.sig):
        return "invalid"
    return "weak" if token.integrity == "basic" else "ok"
