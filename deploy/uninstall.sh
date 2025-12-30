#!/bin/bash
# =============================================================================
# Sentra Tunnel Server - Uninstall Script
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

INSTALL_DIR="/opt/sentra-tunnel"
SERVICE_USER="sentra"

echo -e "${YELLOW}This will completely remove Sentra Tunnel Server${NC}"
echo ""
read -p "Are you sure? (yes/no): " confirm
[[ "$confirm" != "yes" ]] && exit 0

echo ""
read -p "Backup data directory first? (y/N): " backup
if [[ "$backup" == "y" || "$backup" == "Y" ]]; then
    BACKUP_FILE="/tmp/sentra-tunnel-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    tar -czf "$BACKUP_FILE" "$INSTALL_DIR/data" 2>/dev/null || true
    echo -e "${GREEN}Backup saved to: $BACKUP_FILE${NC}"
fi

echo "Stopping services..."
systemctl stop sentra-tunnel 2>/dev/null || true
systemctl disable sentra-tunnel 2>/dev/null || true

echo "Removing systemd service..."
rm -f /etc/systemd/system/sentra-tunnel.service
systemctl daemon-reload

echo "Removing Nginx configuration..."
rm -f /etc/nginx/sites-enabled/sentra-tunnel
rm -f /etc/nginx/sites-available/sentra-tunnel
systemctl reload nginx 2>/dev/null || true

echo "Removing fail2ban configuration..."
rm -f /etc/fail2ban/jail.d/sentra-tunnel.conf
rm -f /etc/fail2ban/filter.d/sentra-tunnel.conf
systemctl restart fail2ban 2>/dev/null || true

echo "Removing log rotation..."
rm -f /etc/logrotate.d/sentra-tunnel

echo "Removing application files..."
rm -rf "$INSTALL_DIR"
rm -rf /var/log/sentra-tunnel

echo "Removing service user..."
userdel "$SERVICE_USER" 2>/dev/null || true

echo ""
echo -e "${GREEN}Uninstallation complete${NC}"
echo ""
echo "Note: The following were NOT removed:"
echo "  - SSL certificates in /etc/letsencrypt/"
echo "  - System packages (python3, nginx, etc.)"
echo "  - Firewall rules"
