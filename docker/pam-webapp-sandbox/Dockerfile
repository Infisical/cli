# Infisical PAM "webapp" sandbox image.
#
# A per-session, headful browser streamed over RDP. The Gateway launches one
# container per web-access session (M3), navigated to the resource's TARGET_URL,
# and the existing RDP MITM bridge connects to the container's local RDP server
# and streams the browser into the user's tab.
#
# Stack (locked by the M0 spine spike — see docs/completed/m0.md):
#   Xvfb (virtual display) <- XTEST/XDamage - freerdp-shadow-cli (TLS, no NLA)
#   openbox (minimal WM) + chromium (--kiosk TARGET_URL)
#
# Security hardening (seccomp, dropped caps, egress lock) is intentionally
# DEFERRED to M6. M1 is "it runs and serves RDP".
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# Browser + virtual display + RDP server + a font set wide enough for real web
# content (Liberation = metric-compatible Arial/Times/Courier; Noto core/CJK +
# color emoji cover most pages). tini gives us correct PID 1 signal/zombie
# handling so the Gateway's SIGTERM tears the container down cleanly (M3).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      xvfb \
      x11-xserver-utils \
      openbox \
      dbus-x11 \
      chromium \
      freerdp2-shadow-x11 \
      fonts-liberation \
      fonts-dejavu-core \
      fonts-noto-core \
      fonts-noto-cjk \
      fonts-noto-color-emoji \
      ca-certificates \
      tini \
 && rm -rf /var/lib/apt/lists/*

# freerdp-shadow's X11 backend PAM-authenticates the connecting RDP user before
# it will mirror the display, even with RDP-level auth off (M0 finding 5). There
# is no real interactive login here — the container runs a single browser as one
# unprivileged user — so we make ONLY the services the shadow server probes
# permissive (a dedicated `freerdp-shadow` policy plus the lightdm/gdm/xdm names
# it falls back to). Unlike the M0 spike we do NOT clobber the global common-auth
# / common-account stacks. The connecting username must resolve to a real account
# (getpwnam after PAM success), so we create the `infisical` user; the webapp
# synthetic account (M2) uses this same username.
#
# NOTE for M6: a compromised browser still can't `su`/login to anything useful
# (no privileged accounts, dropped privs land in M6), but if we later need a
# tighter stance, build FreeRDP with -DWITH_PAM=OFF or switch the RDP server.
RUN set -eux; \
    printf '%s\n' \
      'auth     required pam_permit.so' \
      'account  required pam_permit.so' \
      'password required pam_permit.so' \
      'session  required pam_permit.so' \
      > /etc/pam.d/freerdp-shadow; \
    cp /etc/pam.d/freerdp-shadow /etc/pam.d/lightdm; \
    cp /etc/pam.d/freerdp-shadow /etc/pam.d/gdm; \
    cp /etc/pam.d/freerdp-shadow /etc/pam.d/xdm; \
    useradd -m -s /usr/sbin/nologin infisical; \
    install -d -m 1777 /tmp/.X11-unix

COPY entrypoint.sh healthcheck.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh

# Run unprivileged. Xvfb (its own display), freerdp-shadow (port > 1024, XTEST on
# its own display) and chromium (--no-sandbox) all work without root. Full
# privilege-dropping/seccomp is M6; starting non-root is the cheap part of it.
USER infisical
ENV HOME=/home/infisical

ENV TARGET_URL=about:blank
ENV SCREEN_GEOMETRY=1920x1080x24
ENV RDP_PORT=3389

EXPOSE 3389

# The Gateway waits for the RDP server before connecting the bridge (M3); this
# also lets `docker run` report readiness. The probe reads the listening socket
# passively (see healthcheck.sh) so it does NOT spam freerdp-shadow with bare
# TCP connects.
HEALTHCHECK --interval=5s --timeout=3s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/healthcheck.sh"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
