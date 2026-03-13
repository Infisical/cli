#!/bin/sh
set -e

ssh-keygen -A

adduser -D testuser
echo "testuser:testpass" | chpasswd
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

if [ -n "$SSH_AUTHORIZED_KEY" ]; then
  mkdir -p /home/testuser/.ssh
  echo "$SSH_AUTHORIZED_KEY" > /home/testuser/.ssh/authorized_keys
  chmod 700 /home/testuser/.ssh
  chmod 600 /home/testuser/.ssh/authorized_keys
  chown -R testuser:testuser /home/testuser/.ssh
fi

exec /usr/sbin/sshd -D -e
