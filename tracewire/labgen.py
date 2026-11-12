"""
Lab traffic generator.

Crafts a realistic-looking capture of a small office network with Scapy and
injects known attack episodes on top of benign background traffic. Every
connection is registered with its ground-truth label, so the capture comes
with a labeled dataset for evaluation.

Two "days" are produced with different seeds and different attack variants:
day 1 is used to train the ML model, day 2 is held out for testing. Splitting
by capture (not by random row) prevents the model from seeing flows of the
same attack episode during training and testing.
"""
from __future__ import annotations

import csv
import json
import math
from dataclasses import dataclass, field, asdict

import numpy as np
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, wrpcap

# ---------------------------------------------------------------- topology
GW = "10.10.0.1"
WEB = "10.10.0.10"
DNS_SRV = "10.10.0.11"
FILES = "10.10.0.12"      # ssh + smb
DB = "10.10.0.13"
MONITOR = "10.10.0.5"
SERVERS = [WEB, DNS_SRV, FILES, DB]
CLIENTS = [f"10.10.0.{i}" for i in range(100, 140)]
LIVE_HOSTS = set(SERVERS + CLIENTS + [GW, MONITOR])
EXTERNAL = ["93.184.216.34", "151.101.1.69", "142.250.72.14", "104.16.132.229",
            "13.107.42.14", "185.199.108.153", "52.84.150.11", "23.215.0.136"]
CDN = "151.101.1.69"

OPEN_PORTS = {WEB: {80, 443}, DNS_SRV: {53}, FILES: {22, 445}, DB: {5432}}
for c in CLIENTS:
    OPEN_PORTS[c] = {135, 445}

BENIGN_DOMAINS = ["updates.example.com", "mail.example.com", "intranet.lab.local",
                  "cdn.jsdelivr.net", "api.github.com", "login.microsoftonline.com",
                  "www.wikipedia.org", "fonts.gstatic.com", "time.windows.com",
                  "docs.python.org", "slack.com", "zoom.us", "teams.microsoft.com"]

MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"


@dataclass
class Episode:
    """One injected attack, used for episode-level evaluation (detection + latency)."""
    episode_id: str
    attack: str
    attacker: str
    target: str
    start: float
    end: float
    description: str


@dataclass
class Capture:
    packets: list = field(default_factory=list)
    labels: dict = field(default_factory=dict)       # flow key -> (label, episode_id)
    episodes: list = field(default_factory=list)


class LabNet:
    def __init__(self, seed: int, t0: float, duration: float):
        self.rng = np.random.default_rng(seed)
        self.t0 = t0
        self.duration = duration
        self.cap = Capture()
        self._eph: dict[str, int] = {}
        self._icmp_id = 1000

    # ------------------------------------------------------------ helpers
    def sport(self, host: str) -> int:
        p = self._eph.get(host, int(self.rng.integers(32768, 60000)))
        p = p + 1 if p < 60999 else 32768
        self._eph[host] = p
        return p

    def _emit(self, pkt, t):
        pkt.time = self.t0 + t
        self.cap.packets.append(pkt)

    def _label(self, key, label, ep=""):
        self.cap.labels[key] = (label, ep)

    def _tcp(self, src, dst, sp, dp, flags, seq, ack, payload=0, t=0.0):
        p = Ether(src=MAC_A, dst=MAC_B) / IP(src=src, dst=dst, ttl=64) / \
            TCP(sport=sp, dport=dp, flags=flags, seq=seq & 0xFFFFFFFF, ack=ack & 0xFFFFFFFF, window=64240)
        if payload:
            p = p / Raw(load=b"\x00" * payload)
        self._emit(p, t)

    # ------------------------------------------------------------ TCP patterns
    def tcp_session(self, c, s, dp, t, req, resp, label="benign", ep="", rtt=0.02,
                    think=0.0, server_close=False, sp=None):
        """Full three-way handshake, data both ways, orderly close."""
        sp = sp or self.sport(c)
        self._label(("tcp", c, sp, s, dp), label, ep)
        cs, ss = int(self.rng.integers(1, 2**31)), int(self.rng.integers(1, 2**31))
        self._tcp(c, s, sp, dp, "S", cs, 0, t=t); t += rtt / 2
        self._tcp(s, c, dp, sp, "SA", ss, cs + 1, t=t); t += rtt / 2
        self._tcp(c, s, sp, dp, "A", cs + 1, ss + 1, t=t)
        cs += 1; ss += 1
        sent = 0
        n = 0
        while sent < req:                          # client -> server
            chunk = min(1400, req - sent)
            t += 0.0008
            self._tcp(c, s, sp, dp, "PA", cs, ss, chunk, t=t)
            cs += chunk; sent += chunk; n += 1
            if n % 4 == 0:
                self._tcp(s, c, dp, sp, "A", ss, cs, t=t + rtt / 2)
        t += rtt / 2 + think
        sent = n = 0
        while sent < resp:                         # server -> client
            chunk = min(1400, resp - sent)
            t += 0.0008
            self._tcp(s, c, dp, sp, "PA", ss, cs, chunk, t=t)
            ss += chunk; sent += chunk; n += 1
            if n % 4 == 0:
                self._tcp(c, s, sp, dp, "A", cs, ss, t=t + rtt / 2)
        t += rtt
        if server_close:
            self._tcp(s, c, dp, sp, "FA", ss, cs, t=t); t += rtt / 2
            self._tcp(c, s, sp, dp, "FA", cs, ss + 1, t=t); t += rtt / 2
            self._tcp(s, c, dp, sp, "A", ss + 1, cs + 1, t=t)
        else:
            self._tcp(c, s, sp, dp, "FA", cs, ss, t=t); t += rtt / 2
            self._tcp(s, c, dp, sp, "FA", ss, cs + 1, t=t); t += rtt / 2
            self._tcp(c, s, sp, dp, "A", cs + 1, ss + 1, t=t)
        return t

    def syn_probe(self, c, s, dp, t, label, ep, sp=None, stealth_reply=True):
        """SYN scan probe: closed -> RST/ACK, open -> SYN/ACK then RST, dead host -> nothing."""
        sp = sp or self.sport(c)
        self._label(("tcp", c, sp, s, dp), label, ep)
        seq = int(self.rng.integers(1, 2**31))
        self._tcp(c, s, sp, dp, "S", seq, 0, t=t)
        if s not in LIVE_HOSTS:
            return
        if dp in OPEN_PORTS.get(s, set()):
            ss = int(self.rng.integers(1, 2**31))
            self._tcp(s, c, dp, sp, "SA", ss, seq + 1, t=t + 0.0015)
            if stealth_reply:
                self._tcp(c, s, sp, dp, "R", seq + 1, 0, t=t + 0.002)
        else:
            self._tcp(s, c, dp, sp, "RA", 0, seq + 1, t=t + 0.0012)

    # ------------------------------------------------------------ UDP / ICMP
    def dns_query(self, c, qname, t, qtype="A", label="benign", ep="", txt_len=0):
        sp = self.sport(c)
        self._label(("udp", c, sp, DNS_SRV, 53), label, ep)
        qid = int(self.rng.integers(0, 65535))
        q = Ether(src=MAC_A, dst=MAC_B) / IP(src=c, dst=DNS_SRV) / UDP(sport=sp, dport=53) / \
            DNS(id=qid, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
        self._emit(q, t)
        if qtype == "TXT":
            rr = DNSRR(rrname=qname, type="TXT", ttl=0, rdata="x" * max(txt_len, 1))
        else:
            rr = DNSRR(rrname=qname, type="A", ttl=300,
                       rdata=EXTERNAL[int(self.rng.integers(len(EXTERNAL)))])
        r = Ether(src=MAC_B, dst=MAC_A) / IP(src=DNS_SRV, dst=c) / UDP(sport=53, dport=sp) / \
            DNS(id=qid, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=qname, qtype=qtype), an=rr)
        self._emit(r, t + 0.003 + float(self.rng.random()) * 0.01)

    def ping(self, c, s, t, icmp_id, seq, label="benign", ep=""):
        self._label(("icmp", c, icmp_id, s, 0), label, ep)
        self._emit(Ether() / IP(src=c, dst=s) / ICMP(type=8, id=icmp_id, seq=seq) / Raw(b"\x00" * 32), t)
        if s in LIVE_HOSTS:
            self._emit(Ether() / IP(src=s, dst=c) / ICMP(type=0, id=icmp_id, seq=seq) / Raw(b"\x00" * 32), t + 0.0009)

    # ------------------------------------------------------------ benign background
    def background(self):
        r = self.rng
        D = self.duration
        for c in CLIENTS:
            t = float(r.uniform(0, 30))
            while t < D:
                kind = r.choice(["web_int", "web_ext", "ssh", "smb", "dns_only"],
                                p=[0.28, 0.40, 0.04, 0.12, 0.16])
                if kind == "web_int":
                    dp = int(r.choice([80, 443]))
                    end = self.tcp_session(c, WEB, dp, t, int(r.integers(300, 900)),
                                           int(r.integers(2000, 40000)), rtt=0.002, think=0.01)
                    # web tier talks to the database for each page
                    self.tcp_session(WEB, DB, 5432, t + 0.004, int(r.integers(120, 400)),
                                     int(r.integers(400, 6000)), rtt=0.0008)
                elif kind == "web_ext":
                    dom = BENIGN_DOMAINS[int(r.integers(len(BENIGN_DOMAINS)))]
                    self.dns_query(c, dom, t)
                    ext = EXTERNAL[int(r.integers(len(EXTERNAL)))]
                    for k in range(int(r.integers(1, 4))):       # browsers open a few conns
                        self.tcp_session(c, ext, 443, t + 0.03 + k * 0.01, int(r.integers(500, 1500)),
                                         int(r.integers(3000, 40000)), rtt=float(r.uniform(0.015, 0.09)),
                                         think=float(r.uniform(0.01, 0.2)))
                elif kind == "ssh":
                    self.tcp_session(c, FILES, 22, t, int(r.integers(3000, 20000)),
                                     int(r.integers(8000, 60000)), rtt=0.002, think=float(r.uniform(2, 40)))
                elif kind == "smb":
                    self.tcp_session(c, FILES, 445, t, int(r.integers(1000, 6000)),
                                     int(r.integers(8000, 90000)), rtt=0.002, think=0.02)
                else:
                    dom = BENIGN_DOMAINS[int(r.integers(len(BENIGN_DOMAINS)))]
                    self.dns_query(c, dom, t)
                # benign failures happen on every real network: a retired intranet app on :8080,
                # a stale printer port, an unreachable external host
                if r.random() < 0.04:
                    tgt, port = [(FILES, 8080), (WEB, 8443), ("10.10.0.250", 9100),
                                 ("45.33.32.156", 443)][int(r.integers(4))]
                    self.syn_probe(c, tgt, port, t + 0.5, "benign", "")
                t += float(r.exponential(38))

        # public visitors browsing the company website (benign inbound from the internet)
        visitors = [f"{a}.{int(r.integers(1, 254))}.{int(r.integers(1, 254))}.{int(r.integers(1, 254))}"
                    for a in r.choice([24, 31, 49, 64, 81, 92, 103, 115, 176, 188], 60)]
        t = 0.0
        while t < D:
            v = visitors[int(r.integers(len(visitors)))]
            for k in range(int(r.integers(1, 4))):
                self.tcp_session(v, WEB, int(r.choice([80, 443], p=[0.2, 0.8])), t + k * 0.05,
                                 int(r.integers(300, 900)), int(r.integers(3000, 45000)),
                                 rtt=float(r.uniform(0.03, 0.2)), think=0.01)
            t += float(r.exponential(4))
        # remote administrator: a few SSH sessions in from home (benign external -> port 22)
        for k in range(4):
            self.tcp_session("81.2.69.160", FILES, 22, float(r.uniform(30, D - 300)), int(r.integers(4000, 20000)),
                             int(r.integers(8000, 60000)), rtt=0.04, think=float(r.uniform(5, 60)))

        # monitoring host pings every server every 30 s (one ICMP id per target)
        for i, s in enumerate(SERVERS):
            iid = 200 + i
            for k, t in enumerate(np.arange(5 + i, D, 30)):
                self.ping(MONITOR, s, float(t), iid, k)

        # large benign transfers: OS updates (inbound) and a cloud backup (outbound on 443)
        for _ in range(2):
            c = CLIENTS[int(r.integers(len(CLIENTS)))]
            self.tcp_session(c, "13.107.42.14", 443, float(r.uniform(60, D - 120)), 900,
                             int(r.integers(1_500_000, 2_500_000)), rtt=0.03)
        c = CLIENTS[int(r.integers(len(CLIENTS)))]
        self.tcp_session(c, "52.84.150.11", 443, float(r.uniform(60, D - 200)),
                         int(r.integers(2_000_000, 3_000_000)), 4000, rtt=0.04)

        # benign connection bursts: a heavy web page opening ~45 parallel connections
        for _ in range(3):
            c = CLIENTS[int(r.integers(len(CLIENTS)))]
            t = float(r.uniform(60, D - 60))
            for k in range(45):
                self.tcp_session(c, CDN, 443, t + k * 0.06, 600, int(r.integers(3000, 30000)), rtt=0.02)

    # ------------------------------------------------------------ attacks
    def episode(self, attack, attacker, target, start, end, desc):
        ep = Episode(f"{attack}-{len(self.cap.episodes) + 1}", attack, attacker, target,
                     round(self.t0 + start, 3), round(self.t0 + end, 3), desc)
        self.cap.episodes.append(ep)
        return ep.episode_id

    def port_scan(self, attacker, target, t, ports, rate):
        ep = self.episode("portscan", attacker, target, t, t + len(ports) / rate,
                          f"SYN scan of {len(ports)} ports at {rate}/s")
        for i, p in enumerate(ports):
            self.syn_probe(attacker, target, int(p), t + i / rate + float(self.rng.random()) * 0.005,
                           "portscan", ep)

    def host_sweep(self, attacker, port, t, rate, use_icmp):
        hosts = [f"10.10.0.{i}" for i in range(1, 255)]
        ep = self.episode("sweep", attacker, "10.10.0.0/24", t, t + len(hosts) / rate,
                          f"{'ICMP + ' if use_icmp else ''}TCP/{port} sweep of the /24")
        for i, h in enumerate(hosts):
            ti = t + i / rate
            if use_icmp:
                self._icmp_id += 1
                self.ping(attacker, h, ti, self._icmp_id, 1, "sweep", ep)
            self.syn_probe(attacker, h, port, ti + 0.01, "sweep", ep, stealth_reply=True)

    def syn_flood(self, target, port, t, n, secs):
        ep = self.episode("synflood", "198.51.100.0/24 (spoofed)", f"{target}:{port}", t, t + secs,
                          f"{n} spoofed SYNs in {secs}s")
        for i in range(n):
            src = f"198.51.100.{int(self.rng.integers(1, 200))}"
            sp = int(self.rng.integers(1024, 65535))
            ti = t + float(self.rng.uniform(0, secs))
            self._label(("tcp", src, sp, target, port), "synflood", ep)
            seq = int(self.rng.integers(1, 2**31))
            self._tcp(src, target, sp, port, "S", seq, 0, t=ti)
            if i < n * 0.3:          # backlog fills up, then the server stops answering
                self._tcp(target, src, port, sp, "SA", int(self.rng.integers(1, 2**31)), seq + 1, t=ti + 0.001)

    def brute_force(self, attacker, target, port, t, n, secs):
        ep = self.episode("bruteforce", attacker, f"{target}:{port}", t, t + secs,
                          f"{n} short login attempts against port {port}")
        for i in range(n):
            ti = t + i * secs / n + float(self.rng.random()) * 0.2
            self.tcp_session(attacker, target, port, ti, int(self.rng.integers(400, 700)),
                             int(self.rng.integers(500, 900)), "bruteforce", ep, rtt=0.03,
                             think=0.4, server_close=True)

    def dns_tunnel(self, client, domain, t, n, secs):
        ep = self.episode("dns_tunnel", client, DNS_SRV, t, t + secs,
                          f"{n} TXT queries with encoded labels under {domain}")
        alphabet = np.array(list("abcdefghijklmnopqrstuvwxyz234567"))
        for i in range(n):
            lab1 = "".join(self.rng.choice(alphabet, 40))
            lab2 = "".join(self.rng.choice(alphabet, int(self.rng.integers(12, 30))))
            self.dns_query(client, f"{lab1}.{lab2}.{domain}", t + i * secs / n, qtype="TXT",
                           label="dns_tunnel", ep=ep, txt_len=int(self.rng.integers(60, 200)))

    def stealth_scan(self, attacker, target, t, secs, gap):
        ports = self.rng.permutation(np.arange(1, 6000))
        n = int(secs / gap)
        ep = self.episode("stealth_scan", attacker, target, t, t + secs,
                          f"slow scan, one probe every ~{gap}s ({n} probes)")
        for i in range(n):
            self.syn_probe(attacker, target, int(ports[i]), t + i * gap + float(self.rng.uniform(0, gap / 2)),
                           "stealth_scan", ep)

    def exfil(self, client, dest, port, t, chunks, size):
        ep = self.episode("exfil", client, f"{dest}:{port}", t, t + chunks * 4,
                          f"{chunks} uploads of ~{size // 1000} kB to a non-standard port")
        for i in range(chunks):
            self.tcp_session(client, dest, port, t + i * 4, size + int(self.rng.integers(0, 50000)),
                             300, "exfil", ep, rtt=0.08)


def build_day(day: int, seed: int, duration: float = 1800.0) -> Capture:
    t0 = 1_762_934_400.0 + (day - 1) * 86400   # 2025-11-12 08:00 UTC + day offset
    net = LabNet(seed, t0, duration)
    net.background()
    r = net.rng
    if day == 1:
        net.port_scan("203.0.113.45", FILES, 300, np.arange(1, 1025), rate=60)
        net.host_sweep("10.10.0.66", 445, 520, rate=25, use_icmp=False)
        net.syn_flood(WEB, 80, 760, n=2400, secs=8)
        net.brute_force("203.0.113.77", FILES, 22, 1000, n=110, secs=90)
        net.dns_tunnel("10.10.0.115", "x7k.exfil-lab.net", 1250, n=320, secs=150)
        net.stealth_scan("198.51.100.200", DB, 150, secs=1500, gap=8)
        net.exfil("10.10.0.120", "185.199.110.9", 8443, 1500, chunks=12, size=450_000)
    else:  # held-out day: different attackers, targets, ports, pacing
        net.port_scan("203.0.113.91", WEB, 420, r.choice(np.arange(1, 10000), 700, replace=False), rate=45)
        net.host_sweep("10.10.0.71", 3389, 640, rate=18, use_icmp=True)
        net.syn_flood(WEB, 443, 900, n=2000, secs=10)
        net.brute_force("203.0.113.140", FILES, 22, 1150, n=90, secs=110)
        net.dns_tunnel("10.10.0.127", "q.cdn-sync-lab.org", 1320, n=280, secs=170)
        net.stealth_scan("198.51.100.201", FILES, 100, secs=1600, gap=9)
        net.exfil("10.10.0.104", "185.199.111.20", 4444, 1580, chunks=10, size=500_000)
    net.cap.packets.sort(key=lambda p: p.time)
    return net.cap


def write_capture(cap: Capture, stem: str):
    wrpcap(f"{stem}.pcap", cap.packets)
    with open(f"{stem}.labels.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["proto", "src", "sport", "dst", "dport", "label", "episode_id"])
        for (proto, s, sp, d, dp), (lab, ep) in cap.labels.items():
            w.writerow([proto, s, sp, d, dp, lab, ep])
    with open(f"{stem}.episodes.json", "w") as f:
        json.dump([asdict(e) for e in cap.episodes], f, indent=2)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Generate labeled lab captures")
    ap.add_argument("--out", default="data")
    a = ap.parse_args()
    for day, seed in [(1, 7), (2, 1337)]:
        cap = build_day(day, seed)
        write_capture(cap, f"{a.out}/day{day}")
        print(f"day{day}: {len(cap.packets):,} packets, {len(cap.labels):,} labeled flows, "
              f"{len(cap.episodes)} attack episodes")
