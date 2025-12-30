#!/bin/bash
# =============================================================================
# Sentra Tunnel Server - Ubuntu 24.04 LTS Installation Script
# =============================================================================
#
# Usage: sudo ./install.sh
#
# This script installs and configures the Sentra Tunnel Server on Ubuntu 24.04
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/sentra-tunnel"
SERVICE_USER="sentra"
DOMAIN=""
ADMIN_EMAIL=""

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_ubuntu() {
    if ! grep -q "Ubuntu 24" /etc/os-release 2>/dev/null; then
        log_warning "This script is optimized for Ubuntu 24.04 LTS"
        read -p "Continue anyway? (y/N): " confirm
        [[ "$confirm" != "y" && "$confirm" != "Y" ]] && exit 1
    fi
}

# -----------------------------------------------------------------------------
# Installation Steps
# -----------------------------------------------------------------------------

install_dependencies() {
    log_info "Installing system dependencies..."

    apt-get update
    apt-get install -y \
        python3.12 \
        python3.12-venv \
        python3-pip \
        nginx \
        certbot \
        python3-certbot-nginx \
        sqlite3 \
        curl \
        ufw \
        fail2ban \
        git

    log_success "Dependencies installed"
}

create_user() {
    log_info "Creating service user..."

    if id "$SERVICE_USER" &>/dev/null; then
        log_info "User $SERVICE_USER already exists"
    else
        useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
        log_success "User $SERVICE_USER created"
    fi
}

setup_directories() {
    log_info "Setting up directories..."

    mkdir -p "$INSTALL_DIR"/{app,data,logs,ssl}
    mkdir -p /var/log/sentra-tunnel

    log_success "Directories created"
}

copy_application() {
    log_info "Copying application files..."

    # Copy app directory
    cp -r app/* "$INSTALL_DIR/app/" 2>/dev/null || true
    cp requirements.txt "$INSTALL_DIR/"

    # Create data directory structure
    mkdir -p "$INSTALL_DIR/data"

    log_success "Application files copied"
}

setup_virtualenv() {
    log_info "Setting up Python virtual environment..."

    cd "$INSTALL_DIR"
    python3.12 -m venv venv

    # Activate and install dependencies
    source venv/bin/activate
    pip install --upgrade pip wheel
    pip install -r requirements.txt

    # Install production server
    pip install gunicorn

    deactivate

    log_success "Virtual environment configured"
}

configure_permissions() {
    log_info "Setting permissions..."

    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" /var/log/sentra-tunnel

    # Secure data directory
    chmod 700 "$INSTALL_DIR/data"
    chmod 600 "$INSTALL_DIR/data"/* 2>/dev/null || true

    log_success "Permissions configured"
}

create_systemd_service() {
    log_info "Creating systemd service..."

    cat > /etc/systemd/system/sentra-tunnel.service << 'EOF'
[Unit]
Description=Sentra Tunnel Server
Documentation=https://github.com/sentra/tunnel-server
After=network.target

[Service]
Type=notify
User=sentra
Group=sentra
WorkingDirectory=/opt/sentra-tunnel
Environment="PATH=/opt/sentra-tunnel/venv/bin"
Environment="PYTHONPATH=/opt/sentra-tunnel"

ExecStart=/opt/sentra-tunnel/venv/bin/gunicorn \
    --workers 2 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 127.0.0.1:8000 \
    --timeout 120 \
    --keep-alive 5 \
    --access-logfile /var/log/sentra-tunnel/access.log \
    --error-logfile /var/log/sentra-tunnel/error.log \
    --capture-output \
    app.main:app

ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/sentra-tunnel/data /var/log/sentra-tunnel
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service created"
}

configure_nginx() {
    log_info "Configuring Nginx..."

    # Prompt for domain if not set
    if [[ -z "$DOMAIN" ]]; then
        read -p "Enter your domain (e.g., tunnel.example.com): " DOMAIN
    fi

    cat > /etc/nginx/sites-available/sentra-tunnel << EOF
# Sentra Tunnel Server - Nginx Configuration
# Domain: $DOMAIN

# Rate limiting zones
limit_req_zone \$binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone \$binary_remote_addr zone=api:10m rate=60r/m;
limit_conn_zone \$binary_remote_addr zone=conn:10m;

# Upstream
upstream sentra_backend {
    server 127.0.0.1:8000;
    keepalive 32;
}

# HTTP -> HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    # SSL configuration (will be configured by certbot)
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Modern TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Connection limits
    limit_conn conn 20;

    # Logging
    access_log /var/log/nginx/sentra-tunnel.access.log;
    error_log /var/log/nginx/sentra-tunnel.error.log;

    # Max upload size
    client_max_body_size 10M;

    # WebSocket endpoint for devices
    location /ws {
        proxy_pass http://sentra_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # WebSocket timeouts
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
    }

    # API endpoints
    location /api/ {
        limit_req zone=api burst=20 nodelay;

        proxy_pass http://sentra_backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Login rate limiting
    location /auth/login {
        limit_req zone=login burst=3 nodelay;

        proxy_pass http://sentra_backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Static files (TailwindCSS is loaded from CDN)
    location /static/ {
        alias /opt/sentra-tunnel/app/static/;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }

    # Health check
    location /health {
        proxy_pass http://sentra_backend;
        proxy_http_version 1.1;
        access_log off;
    }

    # All other requests
    location / {
        proxy_pass http://sentra_backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection "";
    }
}
EOF

    # Enable site
    ln -sf /etc/nginx/sites-available/sentra-tunnel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default

    # Test config
    nginx -t

    log_success "Nginx configured"
}

setup_ssl() {
    log_info "Setting up SSL certificate..."

    if [[ -z "$ADMIN_EMAIL" ]]; then
        read -p "Enter admin email for Let's Encrypt: " ADMIN_EMAIL
    fi

    # Create webroot for certbot
    mkdir -p /var/www/certbot

    # Get certificate
    certbot certonly \
        --webroot \
        --webroot-path /var/www/certbot \
        --email "$ADMIN_EMAIL" \
        --agree-tos \
        --no-eff-email \
        -d "$DOMAIN" \
        || log_warning "SSL setup failed - configure manually later"

    # Setup auto-renewal
    systemctl enable certbot.timer
    systemctl start certbot.timer

    log_success "SSL configured"
}

configure_firewall() {
    log_info "Configuring firewall..."

    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH (adjust port if needed)
    ufw allow 22/tcp comment 'SSH'

    # Allow HTTP/HTTPS
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'

    # Enable firewall
    echo "y" | ufw enable

    log_success "Firewall configured"
}

configure_fail2ban() {
    log_info "Configuring fail2ban..."

    cat > /etc/fail2ban/jail.d/sentra-tunnel.conf << 'EOF'
[sentra-tunnel]
enabled = true
port = http,https
filter = sentra-tunnel
logpath = /var/log/nginx/sentra-tunnel.access.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

    cat > /etc/fail2ban/filter.d/sentra-tunnel.conf << 'EOF'
[Definition]
failregex = ^<HOST> .* "POST /auth/login.*" (401|403)
ignoreregex =
EOF

    systemctl restart fail2ban

    log_success "Fail2ban configured"
}

setup_logrotate() {
    log_info "Setting up log rotation..."

    cat > /etc/logrotate.d/sentra-tunnel << 'EOF'
/var/log/sentra-tunnel/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 sentra sentra
    sharedscripts
    postrotate
        systemctl reload sentra-tunnel > /dev/null 2>&1 || true
    endscript
}
EOF

    log_success "Log rotation configured"
}

initialize_database() {
    log_info "Initializing database..."

    cd "$INSTALL_DIR"
    source venv/bin/activate

    python3 -c "
import asyncio
from app.models.database import init_database
asyncio.run(init_database())
print('Database initialized')
"

    deactivate

    # Set permissions on database
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/data/tunnel.db"
    chmod 600 "$INSTALL_DIR/data/tunnel.db"

    log_success "Database initialized"
}

start_services() {
    log_info "Starting services..."

    systemctl enable sentra-tunnel
    systemctl start sentra-tunnel

    systemctl reload nginx

    log_success "Services started"
}

show_summary() {
    echo ""
    echo "=============================================="
    echo -e "${GREEN}Installation Complete!${NC}"
    echo "=============================================="
    echo ""
    echo "Domain: https://$DOMAIN"
    echo ""
    echo "Default Login:"
    echo "  Username: admin"
    echo "  Password: admin"
    echo ""
    echo -e "${YELLOW}IMPORTANT: Change the admin password immediately!${NC}"
    echo ""
    echo "Service Management:"
    echo "  systemctl status sentra-tunnel"
    echo "  systemctl restart sentra-tunnel"
    echo "  journalctl -u sentra-tunnel -f"
    echo ""
    echo "Logs:"
    echo "  /var/log/sentra-tunnel/access.log"
    echo "  /var/log/sentra-tunnel/error.log"
    echo ""
    echo "Configuration:"
    echo "  App: $INSTALL_DIR"
    echo "  Nginx: /etc/nginx/sites-available/sentra-tunnel"
    echo ""
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

main() {
    echo "=============================================="
    echo "Sentra Tunnel Server - Ubuntu 24.04 Installer"
    echo "=============================================="
    echo ""

    check_root
    check_ubuntu

    install_dependencies
    create_user
    setup_directories
    copy_application
    setup_virtualenv
    configure_permissions
    create_systemd_service
    configure_nginx
    setup_ssl
    configure_firewall
    configure_fail2ban
    setup_logrotate
    initialize_database
    start_services

    show_summary
}

main "$@"
