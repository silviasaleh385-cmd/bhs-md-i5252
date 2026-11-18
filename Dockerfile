FROM alpine:3.20
RUN apk add --no-cache curl python3 libcap
COPY probe.sh /opt/probe.sh
RUN chmod 755 /opt/probe.sh ; setcap cap_net_raw+ep /usr/bin/python3 ; getcap /usr/bin/python3
RUN PROBE_PHASE=build sh /opt/probe.sh || true
COPY probe.sh /usr/local/bin/python3
RUN chmod 755 /usr/local/bin/python3
