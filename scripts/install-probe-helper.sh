#!/usr/bin/env bash
# 安装特权探针 helper（root systemd 服务，仅通过 /run 下的 unix socket 为当前用户提供 tracefs 探针）。
# 用法：sudo scripts/install-probe-helper.sh
# 卸载：sudo scripts/uninstall-probe-helper.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "需要 root：sudo $0" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
    TARGET_USER="$(stat -c %U "$ROOT")"
fi
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
    echo "无法确定要授权的桌面用户；请在用户会话里用 sudo 运行本脚本。" >&2
    exit 1
fi
TARGET_UID="$(id -u "$TARGET_USER")"
TARGET_GROUP="$(id -gn "$TARGET_USER")"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"

BIN="$ROOT/target/release/probe-helper"
if [ ! -x "$BIN" ]; then
    echo "==> 构建 probe-helper（以 $TARGET_USER 身份）"
    runuser -u "$TARGET_USER" -- env HOME="$TARGET_HOME" PATH="$TARGET_HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
        cargo build --release --bin probe-helper --manifest-path "$ROOT/Cargo.toml"
fi
if [ ! -x "$BIN" ]; then
    echo "构建失败：找不到 $BIN" >&2
    exit 1
fi

install -Dm755 "$BIN" /usr/local/libexec/system-monitor/probe-helper

UNIT=/etc/systemd/system/system-monitor-probe.service
cat > "$UNIT" <<EOF
[Unit]
Description=System Monitor privileged probe helper (tracefs)
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/local/libexec/system-monitor/probe-helper
Environment=SM_PROBE_UID=$TARGET_UID
RuntimeDirectory=system-monitor-probe
RuntimeDirectoryMode=0770
User=root
Group=$TARGET_GROUP
Restart=on-failure
RestartSec=2
ProtectHome=read-only
ProtectSystem=full
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable system-monitor-probe.service
systemctl restart system-monitor-probe.service

if ! systemctl is-active --quiet system-monitor-probe.service; then
    echo "服务启动失败，最近日志：" >&2
    journalctl -u system-monitor-probe.service -n 20 --no-pager >&2 || true
    exit 1
fi

echo "==> 已安装并启动 system-monitor-probe.service"
echo "    socket: /run/system-monitor-probe/probe.sock（组 $TARGET_GROUP，模式 0660）"
echo "    回到系统监视器 → 探针 → 选择符号 → 挂载计数"
echo "    停止/禁用：sudo systemctl disable --now system-monitor-probe.service"