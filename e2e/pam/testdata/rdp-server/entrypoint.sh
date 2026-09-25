#!/bin/bash
set -e

useradd -m -s /bin/bash testuser
echo "testuser:testpass" | chpasswd

mkdir -p /home/testuser
echo "openbox-session" > /home/testuser/.xsession
chown testuser:testuser /home/testuser/.xsession

if [ ! -f /etc/xrdp/rsakeys.ini ]; then
    xrdp-keygen xrdp auto
fi

mkdir -p /run/dbus
dbus-daemon --system --fork

xrdp-sesman --nodaemon &

exec xrdp --nodaemon
