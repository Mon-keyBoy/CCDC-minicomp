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


#reinstall essential packages that might be backdoored (this includes their binaries)
#note that this does not reinstall the config files
#THIS WOULD BE A LOT FASTER AND BETTER WITH NALA INSTEAD OF APT
packages=(
  curl 
  software-properties-common 
  coreutils 
  net-tools 
  build-essential 
  libssl-dev 
  procps 
  lsof 
  tmux 
  nftables 
  jq 
  tar 
  bash 
  sudo 
  util-linux 
  passwd 
  gnupg 
  findutils 
  grep 
  gawk 
  sed 
  wget 
  gzip 
  login 
  cron 
  systemd 
  mount 
  acl 
  iputils-ping 
  lsb-release 
  iproute2
  zsh
)

for package in "${packages[@]}"; do
  apt install -y --reinstall "$package"
done



#copy ssh config after reinstallation
cp /etc/ssh/sshd_config /var/log/SYSLOG/backs_af_reinstal/sshd_config.bak
#reinstall ssh config file, i really should do more configs here like for docker and
#core services but i don't have time so as proof of concept we are just doing ssh
# rm /etc/ssh/sshd_config
# apt download openssh-server
# dpkg-deb -x openssh-server*.deb tmp/
# cp tmp/etc/ssh/sshd_config /etc/ssh/
# apt install --reinstall openssh-server
#nevermind this doesn't work so i'll just manually audit it

#make sshd config more secure
sed -i 's/^#\?UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config 
sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config 
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication no/' "/etc/ssh/sshd_config" 	
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "/etc/ssh/sshd_config"	
chattr +i "/etc/ssh/sshd_config"
systemctl restart ssh
systemctl start ssh
systemctl enable ssh



#install tools that you want/need
apt install -y vim
apt install -y auditd
apt install debsums -y
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
systemctl stop iptables-legacy
systemctl disable iptables-legacy
systemctl stop iptables-persistent
systemctl disable iptables-persistent

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
apt install -y initramfs-tools
update-initramfs -u

#remove persitance rules
rm -f /etc/iptables/rules.v4 /etc/iptables/rules.v6 
#make nftables the main rules
update-alternatives --set iptables /usr/sbin/iptables-nft
update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
update-alternatives --set arptables /usr/sbin/arptables-nft
update-alternatives --set ebtables /usr/sbin/ebtables-nft
#get rid of all nft rules
nft flush ruleset



#make usefull aliases for all users
#show all the users so you can audit them DO NOT DELETE THE CORE ROOT USERS LIKE TOOR!!!!!!
curl -L -o /usr/local/bin/list_users.sh https://raw.githubusercontent.com/Mon-keyBoy/CCDC-minicomp/refs/heads/main/list_users.sh
chmod +x /usr/local/bin/list_users.sh
echo "alias listusers='/usr/local/bin/list_users.sh'" >> /etc/bash.bashrc
#looks for bad binaries
echo 'alias badbins="find / \( -perm -4000 -o -perm -2000 \) -type f -exec file {} \; 2>/dev/null | grep -v ELF"' >> /etc/bash.bashrc
#show bad or altered files
echo 'alias badfiles="debsums | grep -v 'OK$'"' >> /etc/bash.bashrc 
#alias's i like
echo "alias c='clear'" >> /etc/bash.bashrc 
#alias to look for reverse shells
curl -L -o /usr/local/bin/rev_shells.sh https://raw.githubusercontent.com/Mon-keyBoy/CCDC-minicomp/refs/heads/main/rev_shells.sh
chmod +x /usr/local/bin/rev_shells.sh
echo "alias revshells='/usr/local/bin/rev_shells.sh'" >> /etc/bash.bashrc
#commit the alias's
source /etc/bash.bashrc



#disable cron
systemctl stop cron
systemctl disable cron
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
apt remove --purge -y cups



#disable firewalld and ufw
systemctl disable --now firewalld
systemctl disable --now ufw



#setup nftables table input
nft add table ip filter
nft add chain ip filter input { type filter hook input priority 0 \; }
# Allow established and related traffic
nft add rule ip filter input ct state established,related log accept
#allow rules input
#ssh
nft add rule ip filter input tcp dport 22 accept
#FTP
nft add rule ip filter input tcp dport 21 accept
#FTP
nft add rule ip filter input tcp dport 20 accept
#drop everything else
nft add rule ip filter input drop

#setup nftables table output
nft add chain ip filter output { type filter hook output priority 0 \; }
nft add rule ip filter output ct state established,related log accept
#allow rules output
#ssh
nft add rule ip filter output tcp dport 22 accept
#FTP
nft add rule ip filter output tcp dport 21 accept
#FTP
nft add rule ip filter output tcp dport 20 accept
#drop all other output
nft add rule ip filter output drop

#save the rules to a file and make it immutable
nft list ruleset > /etc/nftables.conf
cp /etc/nftables.conf /var/log/SYSLOG/nftables_rules.bak
chattr +i /etc/nftables.conf
#ensure the nftables service loads the runs on boot
systemctl enable nftables



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
rm ubuntu-lan.sh