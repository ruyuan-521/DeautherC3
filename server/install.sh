#!/bin/bash
# DeautherC3 Packet Server - 服务器端一键安装脚本
# 在服务器上直接运行: bash install.sh
# 或者: curl -sSL https://... | bash  (如果有网盘链接)

set -e

DOMAIN="esp.yuanru.fun"
SERVER_IP="38.244.14.175"
INSTALL_DIR="/root/deautherc3_server"
TCP_PORT=9999
WEB_PORT=8000

echo "====================================================="
echo "  DeautherC3 Packet Server - 安装脚本"
echo "  域名: $DOMAIN"
echo "  服务器: $SERVER_IP"
echo "====================================================="
echo ""

# ─── Step 1: 安装系统依赖 ──────────────────────────────────
echo "[1/6] 安装系统依赖..."
if ! command -v python3 &>/dev/null; then
    echo "  [*] 安装 python3..."
    apt update -qq && apt install -y python3 python3-pip
fi
echo "  [✓] Python3: $(python3 --version 2>&1)"

if ! command -v nginx &>/dev/null; then
    echo "  [*] 安装 nginx..."
    apt update -qq && apt install -y nginx
fi
echo "  [✓] Nginx: $(nginx -v 2>&1)"

# ─── Step 2: 安装 Python 依赖 ───────────────────────────────
echo ""
echo "[2/6] 安装 Python 依赖..."
pip3 install --break-system-packages flask 2>/dev/null || pip3 install flask
echo "  [✓] Flask 已安装"

# ─── Step 3: 创建程序目录和文件 ───────────────────────────
echo ""
echo "[3/6] 创建程序目录..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# 这里需要手动上传 server.py，或者如果是在本地运行则跳过
if [ ! -f "$INSTALL_DIR/server.py" ]; then
    echo "  [!] 请将 server.py 上传到 $INSTALL_DIR/"
    echo "  [!] 可以用 scp 从本地上传，或手动创建"
fi

# ─── Step 4: 配置 Nginx 反代 ──────────────────────────────
echo ""
echo "[4/6] 配置 Nginx 反代..."

cat > /etc/nginx/sites-available/deautherc3 << 'NGINX_EOF'
server {
    listen 80;
    server_name esp.yuanru.fun;

    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # SSE 支持
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400;
    }
}
NGINX_EOF

ln -sf /etc/nginx/sites-available/deautherc3 /etc/nginx/sites-enabled/ 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

echo "  [*] 测试 Nginx 配置..."
if nginx -t 2>&1; then
    echo "  [✓] Nginx 配置正确"
    systemctl restart nginx 2>/dev/null || nginx -s reload 2>/dev/null || true
    echo "  [✓] Nginx 已重启"
else
    echo "  [!] Nginx 配置有误，请检查"
fi

# ─── Step 5: 配置防火墙 ────────────────────────────────────
echo ""
echo "[5/6] 配置防火墙..."
if command -v ufw &>/dev/null; then
    ufw allow 80/tcp 2>/dev/null || true
    ufw allow $TCP_PORT/tcp 2>/dev/null || true
    echo "  [✓] ufw 端口已开放 (80, $TCP_PORT)"
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=80/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port=$TCP_PORT/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    echo "  [✓] firewalld 端口已开放 (80, $TCP_PORT)"
else
    echo "  [i] 未检测到防火墙工具"
    echo "  [⚠️ ] 请在雨云控制台安全组手动开放端口: 80, $TCP_PORT"
fi

# ─── Step 6: 配置 systemd 服务 ────────────────────────────
echo ""
echo "[6/6] 配置 systemd 服务..."

cat > /etc/systemd/system/deauthc3-server.service << SYSTEMD_EOF
[Unit]
Description=DeautherC3 Packet Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/server.py --host 127.0.0.1 --port $WEB_PORT --tcp-port $TCP_PORT
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF

systemctl daemon-reload
systemctl enable deauthc3-server

echo "  [✓] systemd 服务已配置并启用"

# ─── 启动服务 ───────────────────────────────────────────────
echo ""
echo "[*] 启动服务..."
systemctl stop deauthc3-server 2>/dev/null || true
sleep 1
systemctl start deauthc3-server
sleep 2

# ─── 验证 ───────────────────────────────────────────────────
echo ""
echo "====================================================="
echo "  安装完成！正在验证..."
echo "====================================================="
echo ""

# 检查服务状态
if systemctl is-active --quiet deauthc3-server; then
    echo "[✓] deauthc3-server 服务运行中"
else
    echo "[!] 服务未运行，查看日志:"
    journalctl -u deauthc3-server --no-pager -l -n 20
fi

# 测试本地连接
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$WEB_PORT/ 2>/dev/null || echo "fail")
if [ "$HTTP_CODE" = "200" ]; then
    echo "[✓] Web 服务正常 (localhost:$WEB_PORT)"
else
    echo "[!] Web 服务异常 (HTTP $HTTP_CODE)"
fi

# 测试 Nginx 反代
HTTP_CODE2=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/ 2>/dev/null || echo "fail")
if [ "$HTTP_CODE2" = "200" ]; then
    echo "[✓] Nginx 反代正常"
else
    echo "[!] Nginx 反代异常 (HTTP $HTTP_CODE2)"
fi

echo ""
echo "====================================================="
echo "  ✅ 部署完成！"
echo "====================================================="
echo ""
echo "  访问地址:"
echo "    http://$DOMAIN"
echo "    http://$SERVER_IP:$WEB_PORT (直连)"
echo ""
echo "  ESP32 应配置:"
echo "    Server IP:  $SERVER_IP"
echo "    Server Port: $TCP_PORT"
echo ""
echo "  服务管理命令:"
echo "    systemctl status deauthc3-server   # 查看状态"
echo "    journalctl -u deauthc3-server -f   # 查看实时日志"
echo "    systemctl restart deauthc3-server   # 重启"
echo ""
echo "  ⚠️  重要提醒:"
echo "    1. 请在雨云控制台确认安全组已开放端口: 80, $TCP_PORT"
echo "    2. 请确保域名 $DOMAIN 已解析到 $SERVER_IP"
echo "    3. 如果 Nginx 无法访问，检查域名解析是否生效"
echo "====================================================="
