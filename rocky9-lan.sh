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



#stop sshd
systemctl stop ssh
systemctl disable ssh

#reinstall essential packages that might be backdoored (this includes their binaries)
#note that this does not reinstall the config files
packages=(
  curl 
  software-properties-common 
  coreutils 
  net-tools 
  gcc
  make
  libssl-dev
  procps-ng
  lsof 
  tmux 
  nftables 
  jq 
  tar 
  bash 
  sudo 
  openssl 
  util-linux 
  passwd 
  gnupg 
  findutils 
  grep 
  gawk 
  sed 
  wget 
  gzip 
  shadow-utils
  cronie
  systemd 
  openssh-clients
  mount 
  acl 
  iputils
  lsb-release 
  iproute
  zsh
  libpam 
  libpam-modules 
  libpam-modules-bin
)

# Reinstall each package
for package in "${packages[@]}"; do
  if dnf list installed "$package" &>/dev/null; then
    dnf reinstall -y "$package"
  else
    dnf install -y "$package"
  fi
done



#delete openssh-server
dnf remove -y openssh-server



#install tools that you want/need
dnf install -y vim
dnf install -y auditd
systemctl enable auditd
systemctl start auditd



#delete and stop iptables legacy and iptables-nft
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X
iptables -t raw -F
iptables -t raw -X
iptables-legacy -F
iptables-legacy -t nat -F
iptables-legacy -t mangle -F
iptables-legacy -t raw -F
iptables-legacy -X
iptables-nft -F
iptables-nft -t nat -F
iptables-nft -t mangle -F
iptables-nft -t raw -F
iptables-nft -X
systemctl stop iptables
systemctl disable iptables
if systemctl is-active --quiet iptables-legacy; then
  systemctl stop iptables-legacy
  systemctl disable iptables-legacy
fi
if systemctl is-active --quiet iptables-persistent; then
  systemctl stop iptables-persistent
  systemctl disable iptables-persistent
fi



# Define the blacklist configuration file
BLACKLIST_FILE="/etc/modprobe.d/blacklist.conf"
# Check if the file exists, create it if it doesn't
if [ ! -f "$BLACKLIST_FILE" ]; then
    echo "Creating blacklist configuration file at $BLACKLIST_FILE"
    sudo touch "$BLACKLIST_FILE"
fi

# Add the blacklist entries
echo "Blacklisting kernel modules..."
bash -c "cat >> $BLACKLIST_FILE <<EOF
blacklist ip_tables
blacklist iptable_nat
blacklist ip6_tables
blacklist iptable_mangle
blacklist iptable_raw
EOF"

depmod -a
dracut --force

#remove persitance rules
rm -f /etc/iptables/rules.v4 /etc/iptables/rules.v6 
#make nftables the main rules
alternatives --set iptables /usr/sbin/iptables-nft
alternatives --set ip6tables /usr/sbin/ip6tables-nft
alternatives --set arptables /usr/sbin/arptables-nft
alternatives --set ebtables /usr/sbin/ebtables-nft
#get rid of all nft rules
nft flush ruleset



#backup docker before reinstallation later on
mkdir -p /var/log/SYSLOG/backs_bf_reinstal/docker_backup
cp -r /etc/docker /var/log/SYSLOG/backs_bf_reinstal/docker_backup



#make usefull aliases for all users
#show all the users so you can audit them DO NOT DELETE THE CORE ROOT USERS LIKE TOOR!!!!!!
curl -L -o /usr/local/bin/list_users.sh https://raw.githubusercontent.com/Mon-keyBoy/CCDC-minicomp/refs/heads/main/list_users.sh
chmod +x /usr/local/bin/list_users.sh
echo "alias listusers='/usr/local/bin/list_users.sh'" >> /etc/bashrc
#looks for bad binaries
echo 'alias badbins="find / \( -perm -4000 -o -perm -2000 \) -type f -exec file {} \; 2>/dev/null | grep -v ELF"' >> /etc/bash.bashrc
#alias's i like
echo "alias c='clear'" >> /etc/bashrc
#alias to look for reverse shells
curl -L -o /usr/local/bin/rev_shells.sh https://raw.githubusercontent.com/Mon-keyBoy/CCDC-minicomp/refs/heads/main/rev_shells.sh
chmod +x /usr/local/bin/rev_shells.sh
echo "alias revshells='/usr/local/bin/rev_shells.sh'" >> /etc/bashrc
#commit the alias's
source /etc/bashrc



#disable cron
systemctl stop crond
systemctl disable crond
chattr +i /etc/crontab
chattr +i /etc/cron.d
chattr +i /etc/cron.daily
chattr +i /etc/cron.hourly
chattr +i /etc/cron.monthly
chattr +i /etc/cron.weekly



#get rif of cups
systemctl stop cups
systemctl disable cups
systemctl stop cups.service cups.socket cups.path
systemctl disable cups.service cups.socket cups.path
dnf remove -y cups



#disable firewalld and ufw
systemctl disable --now firewalld
systemctl disable --now ufw



#setup nftables table input
nft add table ip filter
nft add chain ip filter input { type filter hook input priority 0 \; }
# Allow established and related traffic
nft add rule ip filter input ct state established,related log accept
#allow rules input
#IMAP
nft add rule ip filter input tcp dport 143 accept
#IMAP over SSL/TLS
nft add rule ip filter input tcp dport 993 accept
#SMTP
nft add rule ip filter input tcp dport 25 accept
#SMTP over SSL/TLS
nft add rule ip filter input tcp dport 465 accept
#SMTP with STARTTLS
nft add rule ip filter input tcp dport 587 accept
#SMTP non-standard port
nft add rule ip filter input tcp dport 2525 accept
#drop everything else
nft add rule ip filter input drop

#setup nftables table output
nft add chain ip filter output { type filter hook output priority 0 \; }
nft add rule ip filter output ct state established,related log accept
#allow rules output
#IMAP
nft add rule ip filter output udp dport 143 accept
#IMAP over SSL/TLS
nft add rule ip filter output tcp dport 993 accept
#SMTP
nft add rule ip filter output tcp dport 25 accept
#SMTP over SSL/TLS
nft add rule ip filter output tcp dport 465 accept
#SMTP with STARTTLS
nft add rule ip filter output tcp dport 587 accept
#SMTP non-standard port
nft add rule ip filter output tcp dport 2525 accept
#drop all other output
nft add rule ip filter output drop

#save the rules to a file and make it immutable
nft list ruleset > /etc/nftables.conf
cp /etc/nftables.conf /var/log/SYSLOG/nftables_rules.bak
chattr +i /etc/nftables.conf
#ensure the nftables service loads the rules on boot
systemctl enable nftables



#start IMAP/SMTP 
systemctl start postfix
systemctl enable postfix
systemctl start dovecot
systemctl enable dovecot



#sharads line to make kernel modules require signatures, you need to reboot to get rid of any loaded kernel modules though
sed -i 's/\(vmlinuz.*\)/\1 module.sig_enforce=1 module.sig_unenforce=0/' /boot/grub/grub.cfg



#make backups immutable
chattr +i /var/log/SYSLOG/backs_bf_reinstal
chattr +i /var/log/SYSLOG/backs_af_reinstal

#script done
echo "."
echo "."
echo "."
echo "."
echo "."
echo "Script Complete!"
rm rocky9-lan.sh