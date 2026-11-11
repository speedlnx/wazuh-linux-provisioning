
#!/usr/bin/env bash
set -Eeuo pipefail

# Wazuh Linux Provisioning v2.1
# Debian / Ubuntu - VM, fisico e Proxmox LXC
# Richiede agente Wazuh già installato.
#
# v2.1: corretto delimitatore EOF nel blocco auditd.

export DEBIAN_FRONTEND=noninteractive

AGENT_CONF="/var/ossec/etc/ossec.conf"
AUDIT_RULES="/etc/audit/rules.d/50-wazuh-security.rules"
CHECK_SCRIPT="/usr/local/sbin/wazuh-privileges-check"
STATE_DIR="/var/lib/wazuh-privileges"
PRIV_LOG="/var/log/wazuh-privileges.log"
BACKUP_DIR="/root/wazuh-provision-backup-$(date +%Y%m%d-%H%M%S)-$$"

log() {
    printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

die() {
    echo "ERRORE: $*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || die "Eseguire come root"
[[ -f /etc/debian_version ]] || die "Richiesta Debian/Ubuntu"
[[ -f "$AGENT_CONF" ]] || die "Agente Wazuh non installato"

for cmd in python3 systemctl getent; do
    command -v "$cmd" >/dev/null || die "Comando mancante: $cmd"
done

getent group sudo >/dev/null || die "Gruppo sudo assente"

VIRT="$(systemd-detect-virt 2>/dev/null || true)"
USE_AUDITD=1

if [[ "$VIRT" == "lxc" ]]; then
    USE_AUDITD=0
fi

log "Host: $(hostname)"
log "Virtualizzazione: ${VIRT:-fisico/non rilevata}"
log "Auditd: $([[ $USE_AUDITD -eq 1 ]] && echo abilitato || echo escluso)"

install -d -m 700 "$BACKUP_DIR"
cp -a "$AGENT_CONF" "$BACKUP_DIR/ossec.conf"

# -------------------------------------------------------
# 1. AUDITD
# -------------------------------------------------------

if [[ $USE_AUDITD -eq 1 ]]; then
    log "Installazione e configurazione auditd"

    apt-get update
    apt-get install -y auditd audispd-plugins

    systemctl enable --now auditd

    install -d -m 755 /etc/audit/rules.d

    if [[ ! -e "$AUDIT_RULES" ]]; then
        cat > "$AUDIT_RULES" <<'EOF'
-w /etc/passwd -p wa -k identity_changes
-w /etc/group -p wa -k identity_changes
-w /etc/gshadow -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
-w /etc/sudoers -p wa -k privilege_changes
-w /etc/sudoers.d -p wa -k privilege_changes
EOF
    else
        log "Regole auditd già presenti: non sovrascritte"
    fi

    augenrules --load
else
    log "Container LXC: auditd non verrà installato o avviato"

    if systemctl list-unit-files auditd.service --no-legend 2>/dev/null |
       grep -q '^auditd.service'; then
        systemctl disable --now auditd 2>/dev/null || true
        systemctl reset-failed auditd 2>/dev/null || true
    fi
fi

# -------------------------------------------------------
# 2. LOG PRIVILEGI
# -------------------------------------------------------

log "Preparazione monitoraggio privilegi"

install -d -m 700 "$STATE_DIR"

touch "$PRIV_LOG"
chown root:root "$PRIV_LOG"
chmod 640 "$PRIV_LOG"

# -------------------------------------------------------
# 3. CONFIGURAZIONE WAZUH AGENT
# -------------------------------------------------------

log "Configurazione raccolta log Wazuh"

USE_AUDITD="$USE_AUDITD" python3 - "$AGENT_CONF" <<'PY'
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

path = Path(sys.argv[1])
original = path.read_text()

root = ET.fromstring("<root>" + original + "</root>")

sources = [
    ("json", "/var/log/wazuh-privileges.log")
]

if os.environ["USE_AUDITD"] == "1":
    sources.append(("audit", "/var/log/audit/audit.log"))

if Path("/var/log/auth.log").exists():
    sources.append(("syslog", "/var/log/auth.log"))
else:
    sources.append(("journald", "journald"))

existing = {
    (node.findtext("log_format"), node.findtext("location"))
    for node in root.iter("localfile")
}

blocks = []

for fmt, location in sources:
    if (fmt, location) in existing:
        continue

    if fmt == "journald":
        blocks.append("""  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
    <filter field="_SYSTEMD_UNIT">^ssh(d)?\\.service$</filter>
  </localfile>
""")
    else:
        blocks.append(f"""  <localfile>
    <log_format>{fmt}</log_format>
    <location>{location}</location>
  </localfile>
""")

if not blocks:
    print("Sorgenti già presenti")
    sys.exit(0)

marker = "</ossec_config>"
position = original.rfind(marker)

if position < 0:
    raise SystemExit("Chiusura ossec_config non trovata")

updated = original[:position] + "\n".join(blocks) + original[position:]
ET.fromstring("<root>" + updated + "</root>")

path.write_text(updated)
print("Nuove sorgenti:", len(blocks))
PY

# -------------------------------------------------------
# 4. SCRIPT PRIVILEGI
# -------------------------------------------------------

log "Installazione rilevatore privilegi"

cat > "$CHECK_SCRIPT" <<'PY'
#!/usr/bin/env python3
import fcntl
import grp
import json
import os
import pwd
from datetime import datetime, timezone
from pathlib import Path

BASE = Path("/var/lib/wazuh-privileges")
STATE = BASE / "state.json"
LOCK = BASE / "check.lock"
LOG = Path("/var/log/wazuh-privileges.log")

def snapshot():
    sudo_group = grp.getgrnam("sudo")
    sudo_users = set(sudo_group.gr_mem)

    sudo_users.update(
        u.pw_name for u in pwd.getpwall()
        if u.pw_gid == sudo_group.gr_gid
    )

    uid0_users = {
        u.pw_name for u in pwd.getpwall()
        if u.pw_uid == 0
    }

    return {
        "sudo_users": sorted(sudo_users),
        "uid0_users": sorted(uid0_users)
    }

def save_state(current):
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(current, indent=2) + "\n")
    tmp.chmod(0o600)
    tmp.replace(STATE)

def main():
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)

    with LOCK.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = snapshot()

        if not STATE.exists():
            save_state(current)
            print("Baseline inizializzata")
            return

        previous = json.loads(STATE.read_text())
        events = []

        for category in ("sudo_users", "uid0_users"):
            before = set(previous[category])
            after = set(current[category])

            for user in sorted(after - before):
                events.append((category, "added", user))

            for user in sorted(before - after):
                events.append((category, "removed", user))

        with LOG.open("a") as log:
            for category, action, user in events:
                event = {
                    "integration": "privilege_monitor",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "privilege_category": category,
                    "action": action,
                    "user": user,
                    "host": os.uname().nodename
                }
                log.write(json.dumps(event) + "\n")

            log.flush()
            os.fsync(log.fileno())

        save_state(current)
        print(f"Privilege changes detected: {len(events)}")

if __name__ == "__main__":
    main()
PY

chmod 700 "$CHECK_SCRIPT"
python3 -m py_compile "$CHECK_SCRIPT"

# -------------------------------------------------------
# 5. SYSTEMD
# -------------------------------------------------------

log "Configurazione systemd"

cat > /etc/systemd/system/wazuh-privileges.service <<'EOF'
[Unit]
Description=Wazuh Linux privilege change detector

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/wazuh-privileges-check
EOF

cat > /etc/systemd/system/wazuh-privileges.path <<'EOF'
[Unit]
Description=Watch Linux account privilege files

[Path]
PathChanged=/etc/passwd
PathChanged=/etc/group
Unit=wazuh-privileges.service

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/logrotate.d/wazuh-privileges <<'EOF'
/var/log/wazuh-privileges.log {
    weekly
    rotate 12
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF

systemctl daemon-reload
systemctl enable --now wazuh-privileges.path
systemctl start wazuh-privileges.service

# -------------------------------------------------------
# 6. AGENTE WAZUH
# -------------------------------------------------------

log "Riavvio agente Wazuh"

systemctl restart wazuh-agent

# -------------------------------------------------------
# 7. VERIFICHE
# -------------------------------------------------------

log "Verifica servizi"

systemctl is-active wazuh-agent
systemctl is-active wazuh-privileges.path

if [[ $USE_AUDITD -eq 1 ]]; then
    systemctl is-active auditd
    echo
    echo "Regole auditd:"
    auditctl -l | grep -E 'identity_changes|privilege_changes' || true
else
    echo "auditd: N/A (container LXC)"
fi

echo
echo "Stato privilegi:"
cat "$STATE_DIR/state.json"

echo
echo "Provisioning completato."
echo "Backup: $BACKUP_DIR"
echo "Ricordare assegnazione al gruppo Wazuh linux-common."
