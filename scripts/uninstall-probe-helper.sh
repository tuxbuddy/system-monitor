#!/usr/bin/env bash
# 停止并移除特权探针 helper。
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "需要 root：sudo $0" >&2
    exit 1
fi

systemctl disable --now system-monitor-probe.service 2>/dev/null || true
rm -f /etc/systemd/system/system-monitor-probe.service
systemctl daemon-reload
rm -f /usr/local/libexec/system-monitor/probe-helper
rmdir /usr/local/libexec/system-monitor 2>/dev/null || true
rm -f /run/system-monitor-probe/probe.sock
rmdir /run/system-monitor-probe 2>/dev/null || true

echo "已移除 system-monitor-probe.service 和 probe-helper。"
echo "若 tracefs 里还有残留事件，重新启动一次 helper 会自动清理它们。"