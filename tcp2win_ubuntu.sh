#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractiv

DEF_IFACE=`ip r | grep default | head -1 |  cut -f 5 -d ' '`

apt update -y
apt upgrade -y

apt-get -y install build-essential python3-dev libnetfilter-queue-dev
apt install -y python3-pip
pip install NetfilterQueue
pip install scapy

mkdir -p ${HOME}/tcp2win
cat > ${HOME}/tcp2win/tcp2win.py << eof
#!/usr/bin/env python3
from netfilterqueue import NetfilterQueue
from scapy.all import *
def print_and_accept(PKT):
    data = PKT.get_payload()
    pkt = IP(data)
    opt = pkt[TCP].options
    if len(opt) == 6:
        pkt[TCP].options = [opt[0], opt[1], opt[5], opt[2], opt[4], opt[3]]
        if pkt[TCP].window != 64240:
            pkt[TCP].window = 64240
            pkt[TCP].chksum = None
            pkt[IP].chksum = None
        send(pkt)
        PKT.drop()
    else:
        PKT.accept()
nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
conf.verb = 0
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')
nfqueue.unbind()
eof

chmod +x ${HOME}/tcp2win/tcp2win.py

cat > /etc/systemd/system/tcp2win.service << eof
[Unit]
Description=TCP fingerprint fix
After=network.target
Wants=network.target

[Service]
User=root
Type=simple
ExecStartPre=iptables -I OUTPUT -o $DEF_IFACE --protocol tcp --tcp-flags ALL SYN -j NFQUEUE --queue-num 1
ExecStart=${HOME}/tcp2win/tcp2win.py
ExecStopPost=iptables -D OUTPUT -o $DEF_IFACE --protocol tcp --tcp-flags ALL SYN -j NFQUEUE --queue-num 1
Restart=always

[Install]
WantedBy=multi-user.target
eof

systemctl daemon-reload
systemctl enable --now tcp2win.service
systemctl restart tcp2win.service

echo "net.ipv4.tcp_window_scaling=1"         >> /etc/sysctl.conf
echo "net.ipv4.ip_default_ttl=128"           >> /etc/sysctl.conf
echo "net.ipv4.tcp_timestamps=0"             >> /etc/sysctl.conf
echo "net.ipv4.tcp_rmem=4096 130000 8388608" >> /etc/sysctl.conf
echo "net.ipv4.tcp_wmem=4096 141000 8388608" >> /etc/sysctl.conf

echo 1   > /proc/sys/net/ipv4/tcp_window_scaling
echo 128 > /proc/sys/net/ipv4/ip_default_ttl
echo 0   > /proc/sys/net/ipv4/tcp_timestamps
echo "4096 130000 8388608" > /proc/sys/net/ipv4/tcp_rmem
echo "4096 141000 8388608" > /proc/sys/net/ipv4/tcp_wmem

echo 
echo '***********************************************'
echo '* TCP fingerprint was installed successfully! *'
echo '***********************************************'
echo 
