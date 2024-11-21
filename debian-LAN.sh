#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (use sudo)."
  exit 1
fi

#install tools that you want
apt install -y vim
apt install -y auditd
systemctl enable auditd
systemctl start auditd

#make a hidden directory for backups (the directory name is SYSLOG)
mkdir /var/log/SYSLOG

#make usefull aliases for all users
echo 'alias auditusers="awk -F: '\''($3 == 0) || ($3 >= 1000 && $3 < 65534) {print $1}'\'' /etc/passwd"' >> /etc/bash.bashrc
echo 'alias badbins="find / \( -perm -4000 -o -perm -2000 \) -type f -exec file {} \; 2>/dev/null | grep -v ELF"' >> /etc/bash.bashrc




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
apt remove --purge -y cups

#delete all nftables and legacy rules
iptables -F
iptables -X
nft flush ruleset

#make sshd config more secure
sed -i 's/^#\?UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config 
sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config 
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication no/' "/etc/ssh/sshd_config" 	
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "/etc/ssh/sshd_config"	
chattr +i "/etc/ssh/sshd_config"
systemctl restart sshd

#since this is a LAN box we will remove sshd
systemctl stop sshd
systemctl disable sshd
apt remove -y openssh-server

#setup basic firewall rules


#get webmin
echo "deb http://download.webmin.com/download/repository sarge contrib" | tee /etc/apt/sources.list.d/webmin.list
wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -
apt install -y webmin --install-recommends

