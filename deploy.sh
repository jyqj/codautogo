#!/bin/bash
# ============================================================
#  codex 注册机 一键部署脚本
#  用法：bash deploy.sh
#  运行后输入服务器地址即可自动打包、上传、安装依赖、后台运行
# ============================================================

set -e

# -------- 颜色 --------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# -------- 用户输入 --------
echo ""
echo "========================================="
echo "  Codex 注册机 → 服务器一键部署"
echo "========================================="
echo ""

read -p "请输入 SSH 别名或地址 (如 server1 或 root@1.2.3.4): " SSH_HOST
[[ -z "$SSH_HOST" ]] && error "服务器不能为空"

read -p "服务器部署目录 (默认 /root/codex): " REMOTE_DIR
REMOTE_DIR=${REMOTE_DIR:-/root/codex}

echo ""
info "目标: ${SSH_HOST} → ${REMOTE_DIR}"
echo ""

# -------- 本地路径 --------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCHIVE="/tmp/codex_deploy_$(date +%s).tar.gz"

# -------- 打包（排除不需要的目录） --------
info "打包项目文件..."
cd "$SCRIPT_DIR"

tar czf "$ARCHIVE" \
    --exclude='./venv' \
    --exclude='./__pycache__' \
    --exclude='./.git' \
    .

ARCHIVE_SIZE=$(du -sh "$ARCHIVE" | cut -f1)
info "打包完成: ${ARCHIVE} (${ARCHIVE_SIZE})"

# -------- 上传 --------
info "上传到服务器..."
ssh "$SSH_HOST" "mkdir -p ${REMOTE_DIR}"
scp "$ARCHIVE" "${SSH_HOST}:${REMOTE_DIR}/codex_deploy.tar.gz"
info "上传完成"

# -------- 远程部署 --------
info "在服务器上解压并编译 Go 程序..."
ssh "$SSH_HOST" bash -s "$REMOTE_DIR" << 'REMOTE_SCRIPT'
REMOTE_DIR="$1"
set -e

cd "$REMOTE_DIR"

# 解压（覆盖旧文件）
tar xzf codex_deploy.tar.gz
rm -f codex_deploy.tar.gz

echo "[+] 文件解压完成"

# 安装 Go（如果没有）
if ! command -v go &>/dev/null; then
    echo "[+] 安装 Go..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq golang-go
    elif command -v yum &>/dev/null; then
        yum install -y golang
    else
        echo "[!] 无法自动安装 Go，请手动安装"
        exit 1
    fi
fi

echo "[+] 编译 Go 程序..."
mkdir -p bin
go build -o bin/codex ./cmd/codex
go build -o bin/codex-server ./cmd/server
go build -o bin/sentinelpow ./cmd/sentinelpow || true

# 停止旧进程（如果有）
if pgrep -f "/bin/codex|bin/codex" >/dev/null 2>&1; then
    echo "[+] 停止旧进程..."
    pkill -f "/bin/codex|bin/codex" || true
    sleep 2
fi

# 后台启动
echo "[+] 启动 Go 主程序..."
nohup ./bin/codex > codex.log 2>&1 &
NEW_PID=$!
sleep 2

# 检查是否成功启动
if kill -0 $NEW_PID 2>/dev/null; then
    echo "[✓] codex 已启动 (PID: $NEW_PID)"
    echo "[✓] 日志文件: ${REMOTE_DIR}/codex.log"
    echo ""
    echo "    查看日志: tail -f ${REMOTE_DIR}/codex.log"
    echo "    停止运行: kill $NEW_PID"
else
    echo "[✗] 启动失败，查看日志:"
    tail -20 codex.log
    exit 1
fi
REMOTE_SCRIPT

# -------- 清理本地 --------
rm -f "$ARCHIVE"

echo ""
info "========================================="
info "  部署完成！"
info "========================================="
info ""
info "  查看日志: ssh ${SSH_HOST} 'tail -f ${REMOTE_DIR}/codex.log'"
info "  停止运行: ssh ${SSH_HOST} 'pkill -f bin/codex'"
info "  重新启动: ssh ${SSH_HOST} 'cd ${REMOTE_DIR} && nohup ./bin/codex > codex.log 2>&1 &'"
echo ""
