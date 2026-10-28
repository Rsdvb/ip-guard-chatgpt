set -e
install -d -o root -g root -m 0755 /usr/lib/ipguard
install -o root -g root -m 0755 '/opt/IP Guard/resources/linux-native/ipguard-system' /usr/lib/ipguard/ipguard-system
install -o root -g root -m 0644 '/opt/IP Guard/resources/linux-source/ipguard@.service' /etc/systemd/system/ipguard@.service
install -o root -g root -m 0644 '/opt/IP Guard/resources/linux-source/com.ip-guard.system.policy' /usr/share/polkit-1/actions/com.ip-guard.system.policy
systemctl daemon-reload
while read -r unit rest; do
  case "$unit" in ipguard@*.service)
    uid=$(printf '%s' "$unit" | sed -n 's/^ipguard@\([0-9][0-9]*\)\.service$/\1/p')
    case "$uid" in ''|*[!0-9]*) continue ;; esac
    if systemctl is-enabled --quiet "$unit"; then systemctl restart "$unit"; fi
  ;; esac
done < <(systemctl list-units --all --plain --no-legend 'ipguard@*.service')
