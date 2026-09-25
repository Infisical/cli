#!/bin/sh
set -e

SSH_USER="${SSH_USER:-infisical}"
SSH_MODE="${SSH_MODE:?SSH_MODE must be password | key}"

ssh-keygen -A
if ! id "$SSH_USER" >/dev/null 2>&1; then
  adduser -D "$SSH_USER"
fi

case "$SSH_MODE" in
  password)
    SSH_PASSWORD="${SSH_PASSWORD:-Infisical@123}"
    echo "$SSH_USER:$SSH_PASSWORD" | chpasswd
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    ;;

  key)
    # unusable password so chpasswd doesn't block pubkey auth (Alpine quirk)
    echo "$SSH_USER:*" | chpasswd -e
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

    KEY_FILE="/ssh-keys/id_ed25519"
    if [ ! -f "$KEY_FILE" ]; then
      mkdir -p "$(dirname "$KEY_FILE")"
      ssh-keygen -t ed25519 -f "$KEY_FILE" -N "" -C "$SSH_USER@ssh-server-key"
      echo "==> Generated new ed25519 key pair at $KEY_FILE"
    fi
    USER_HOME=$(eval echo "~$SSH_USER")
    mkdir -p "$USER_HOME/.ssh"
    cp "${KEY_FILE}.pub" "$USER_HOME/.ssh/authorized_keys"
    chmod 700 "$USER_HOME/.ssh"
    chmod 600 "$USER_HOME/.ssh/authorized_keys"
    chown -R "$SSH_USER:$SSH_USER" "$USER_HOME/.ssh"
    ;;

  *)
    echo "Unknown SSH_MODE: $SSH_MODE (expected password | key)" >&2
    exit 1
    ;;
esac

exec /usr/sbin/sshd -D -e
