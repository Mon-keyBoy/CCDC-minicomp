#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (use sudo)."
  exit 1
fi

mkdir -p /var/log/SYSLOG
mkdir -p /var/log/SYSLOG/backs_bf_reinstal
mkdir -p /var/log/SYSLOG/backs_af_reinstal
cp /etc/ssh/sshd_config /var/log/SYSLOG/backs_bf_reinstal/sshd_config.bak
cp /etc/ssh/sshd_config /var/log/SYSLOG/backs_af_reinstal/sshd_config.bak
sed -i 's/^#\?UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config 
sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config 
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication no/' "/etc/ssh/sshd_config" 	
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "/etc/ssh/sshd_config"	
chflags schg /etc/ssh/sshd_config
service sshd restart
pkg install -y vim auditdistd
sysrc auditdistd_enable="YES"
service auditdistd start
pfctl -F all
service pf stop
sysrc pf_enable="NO"
echo "" > /etc/pf.conf
nft flush ruleset
rm -f /etc/nftables.conf
BLACKLIST_FILE="/boot/loader.conf"
if [ ! -f "$BLACKLIST_FILE" ]; then
    echo "Creating blacklist configuration file at $BLACKLIST_FILE"
    touch "$BLACKLIST_FILE"
fi
echo "Blacklisting kernel modules..."
cat >> "$BLACKLIST_FILE" <<EOF
# Blacklist unnecessary modules
ipfw_load="NO"
ipfw_nat_load="NO"
ip6fw_load="NO"
ip_mroute_load="NO"
EOF
kldstat | grep -E "ipfw|ipfw_nat|ip6fw|ip_mroute" | while read -r line; do
    module=$(echo "$line" | awk '{print $NF}')
    echo "Unloading $module..."
    kldunload "$module" || echo "Failed to unload $module"
done
sysrc pf_enable="NO"
sysrc ipfw_enable="NO"
sysrc nftables_enable="YES"
nft flush ruleset
curl -L -o /usr/local/bin/list_users.sh https://raw.githubusercontent.com/Mon-keyBoy/CCDC-minicomp/refs/heads/main/list_users.sh
chmod +x /usr/local/bin/list_users.sh
echo "alias listusers='/usr/local/bin/list_users.sh'" >> /usr/share/skel/dot.cshrc
echo "alias listusers='/usr/local/bin/list_users.sh'" >> /usr/share/skel/dot.shrc
curl -L -o /usr/local/bin/rev_shells.sh https://raw.githubusercontent.com/Mon-keyBoy/CCDC-minicomp/refs/heads/main/rev_shells.sh
chmod +x /usr/local/bin/rev_shells.sh
echo "alias revshells='/usr/local/bin/rev_shells.sh'" >> /usr/share/skel/dot.cshrc
echo "alias revshells='/usr/local/bin/rev_shells.sh'" >> /usr/share/skel/dot.shrc
echo "alias listusers='pw usershow -a'" >> /usr/share/skel/dot.cshrc
echo "alias listusers='pw usershow -a'" >> /usr/share/skel/dot.shrc
echo "alias badbins=\"find / -perm +6000 -type f -exec file {} \\; | grep -v ELF\"" >> /usr/share/skel/dot.cshrc
echo "alias badbins=\"find / -perm +6000 -type f -exec file {} \\; | grep -v ELF\"" >> /usr/share/skel/dot.shrc
echo "alias c='clear'" >> /usr/share/skel/dot.cshrc
echo "alias c='clear'" >> /usr/share/skel/dot.shrc
echo "alias badfiles=\"pkg check -s\"" >> /usr/share/skel/dot.cshrc
echo "alias badfiles=\"pkg check -s\"" >> /usr/share/skel/dot.shrc
source /usr/share/skel/dot.cshrc
source /usr/share/skel/dot.shrc
source ~/.cshrc
source ~/.shrc
service cron stop
sysrc cron_enable="NO"
chflags schg /etc/crontab
service cups stop
sysrc cups_enable="NO"
pkg delete -y cups
kldstat | grep -q nftables || kldload nftables
NFTABLES_CONF="/etc/nftables.conf"
cat > "$NFTABLES_CONF" <<EOF
table ip filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related log accept
        tcp dport 22 accept  # Allow SSH
        tcp dport 3306 accept  # Allow MySQL
        tcp dport 33060 accept  # Allow MySQL
    }

    chain output {
        type filter hook output priority 0; policy drop;
        ct state established,related log accept
        tcp dport 22 accept  # Allow SSH
        tcp dport 3306 accept  # Allow MySQL
        tcp dport 33060 accept  # Allow MySQL
    }
}
EOF
nft flush ruleset
nft -f "$NFTABLES_CONF"

# Create a backup of the nftables rules
BACKUP_DIR="/var/log/SYSLOG"
mkdir -p "$BACKUP_DIR"
cp "$NFTABLES_CONF" "$BACKUP_DIR/nftables_rules.bak"

# Make the nftables configuration file immutable
chflags schg "$NFTABLES_CONF"

# Ensure the nftables service starts on boot
sysrc nftables_enable="YES"
service nftables start

echo "nftables firewall rules applied and saved. Configuration made immutable."



# Enforce stricter kernel controls using securelevel
sysctl kern.securelevel=2
echo "kern_securelevel_enable=YES" >> /etc/rc.conf
echo "kern_securelevel=2" >> /etc/rc.conf

# Make backup directories immutable
chflags schg /var/log/SYSLOG/backs_bf_reinstal
chflags schg /var/log/SYSLOG/backs_af_reinstal

# Print completion message
echo "..."
echo "Script Complete!"

# Remove unnecessary script files
rm -f ubuntu-lan.sh