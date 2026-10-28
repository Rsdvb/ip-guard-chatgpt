case "$1" in
  upgrade|failed-upgrade|abort-install|abort-upgrade|disappear) ;;
  *)
    if [ -x /usr/lib/ipguard/ipguard-system ]; then /usr/lib/ipguard/ipguard-system recover-all || exit 1; fi
    rm -f -- /usr/lib/ipguard/ipguard-system /etc/systemd/system/ipguard@.service /usr/share/polkit-1/actions/com.ip-guard.system.policy
    rmdir -- /usr/lib/ipguard 2>/dev/null || true
    systemctl daemon-reload
    ;;
esac
