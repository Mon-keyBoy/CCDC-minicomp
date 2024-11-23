#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (use sudo)."
  exit 1
fi



#make a hidden directory for backups (the directory name is SYSLOG)
mkdir -p /var/log/SYSLOG
#make backup files
mkdir -p /var/log/SYSLOG/backs_bf_reinstal
mkdir -p /var/log/SYSLOG/backs_af_reinstal



cp /etc/ssh/sshd_config /var/log/SYSLOG/backs_bf_reinstal/sshd_config.bak




#copy ssh config after reinstallation
cp /etc/ssh/sshd_config /var/log/SYSLOG/backs_af_reinstal/sshd_config.bak


#make sshd config more secure
sed -i 's/^#\?UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config 
sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config 
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication no/' "/etc/ssh/sshd_config" 	
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "/etc/ssh/sshd_config"	
chflags schg /etc/ssh/sshd_config
service sshd restart



#install tools that you want/need
pkg install -y vim auditdistd
sysrc auditdistd_enable="YES"
service auditdistd start


#delete and stop freebsd firewalls
pfctl -F all
service pf stop
sysrc pf_enable="NO"
echo "" > /etc/pf.conf
nft flush ruleset
rm -f /etc/nftables.conf



# Define the kernel module blacklist configuration file
BLACKLIST_FILE="/boot/loader.conf"

# Check if the file exists, create it if it doesn't
if [ ! -f "$BLACKLIST_FILE" ]; then
    echo "Creating blacklist configuration file at $BLACKLIST_FILE"
    touch "$BLACKLIST_FILE"
fi

# Add the blacklist entries
echo "Blacklisting kernel modules..."
cat >> "$BLACKLIST_FILE" <<EOF
# Blacklist unnecessary modules
ipfw_load="NO"
ipfw_nat_load="NO"
ip6fw_load="NO"
ip_mroute_load="NO"
EOF

# Unload the kernel modules if they are currently loaded
kldstat | grep -E "ipfw|ipfw_nat|ip6fw|ip_mroute" | while read -r line; do
    module=$(echo "$line" | awk '{print $NF}')
    echo "Unloading $module..."
    kldunload "$module" || echo "Failed to unload $module"
done




#remove persitance rules
#make nftables the main rules
sysrc pf_enable="NO"
sysrc ipfw_enable="NO"
sysrc nftables_enable="YES"
#get rid of all nft rules
nft flush ruleset



# Define useful aliases for all users in FreeBSD

# Create and download scripts for auditing users and detecting reverse shells
curl -L -o /usr/local/bin/list_users.sh https://raw.githubusercontent.com/Mon-keyBoy/CCDC-minicomp/refs/heads/main/list_users.sh
chmod +x /usr/local/bin/list_users.sh
echo "alias listusers='/usr/local/bin/list_users.sh'" >> /usr/share/skel/dot.cshrc
echo "alias listusers='/usr/local/bin/list_users.sh'" >> /usr/share/skel/dot.shrc

curl -L -o /usr/local/bin/rev_shells.sh https://raw.githubusercontent.com/Mon-keyBoy/CCDC-minicomp/refs/heads/main/rev_shells.sh
chmod +x /usr/local/bin/rev_shells.sh
echo "alias revshells='/usr/local/bin/rev_shells.sh'" >> /usr/share/skel/dot.cshrc
echo "alias revshells='/usr/local/bin/rev_shells.sh'" >> /usr/share/skel/dot.shrc

# Alias to find users
echo "alias listusers='pw usershow -a'" >> /usr/share/skel/dot.cshrc
echo "alias listusers='pw usershow -a'" >> /usr/share/skel/dot.shrc

# Alias to find SUID/SGID binaries
echo "alias badbins=\"find / -perm +6000 -type f -exec file {} \\; | grep -v ELF\"" >> /usr/share/skel/dot.cshrc
echo "alias badbins=\"find / -perm +6000 -type f -exec file {} \\; | grep -v ELF\"" >> /usr/share/skel/dot.shrc

# Alias to clear the screen
echo "alias c='clear'" >> /usr/share/skel/dot.cshrc
echo "alias c='clear'" >> /usr/share/skel/dot.shrc

# Alias to show bad or altered files (no `debsums` in FreeBSD, adjust accordingly)
echo "alias badfiles=\"pkg check -s\"" >> /usr/share/skel/dot.cshrc
echo "alias badfiles=\"pkg check -s\"" >> /usr/share/skel/dot.shrc

# Apply aliases to the current user's shell
source /usr/share/skel/dot.cshrc
source /usr/share/skel/dot.shrc
source ~/.cshrc
source ~/.shrc




# Disable and remove unnecessary services (cron and cups)
service cron stop
sysrc cron_enable="NO"
chflags schg /etc/crontab

service cups stop
sysrc cups_enable="NO"
pkg delete -y cups




#!/bin/sh

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root (use sudo)."
  exit 1
fi

# Load the nftables kernel module (if not already loaded)
kldstat | grep -q nftables || kldload nftables

# Create the nftables configuration
NFTABLES_CONF="/etc/nftables.conf"

# Define the ruleset
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

# Flush existing rules and apply the new ruleset
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