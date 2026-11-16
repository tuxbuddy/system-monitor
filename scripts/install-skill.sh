#!/usr/bin/env bash
# 把仓库内的 system-monitor skill 同步到 Qoder 用户技能目录。
# 用法：scripts/install-skill.sh
#       QODER_SKILLS_DIR=/path/to/skills scripts/install-skill.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${QODER_SKILLS_DIR:-$HOME/.qoder-cn/skills}/system-monitor"

mkdir -p "$DEST"
cp "$ROOT/skills/system-monitor/SKILL.md" "$DEST/SKILL.md"
echo "已同步 skill 到 $DEST/SKILL.md"