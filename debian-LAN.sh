#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (use sudo)."
  exit 1
fi

#reinstall core utilities and services, make backups of important shit before and after
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#reinstall essential config files (like ssh) and binaries 
#binaries IDK IF THESE ARE BINARIES AND THERE ARE DEF MORE YOU SHOULD ADD TO THIS LIST
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
apt install -y --reinstall coreutils openssh-server net-tools build-essential libssl-dev procps lsof tmux

#install tools that you want
apt install -y vim
apt install -y auditd
apt install debsums -y
systemctl enable auditd
systemctl start auditd

#make a hidden directory for backups (the directory name is SYSLOG)
mkdir /var/log/SYSLOG

#make usefull aliases for all users
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
#do not blobk port 10000 bc ur running webmin on that
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#get webmin
echo "deb http://download.webmin.com/download/repository sarge contrib" | tee /etc/apt/sources.list.d/webmin.list
wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -
apt install -y webmin --install-recommends

#make a recursive copy of your backups and put it in another location
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#show bad or altered files
debsums | grep -v 'OK$' 

#show all the users so you can audit them DO NOT DELETE THE CORE ROOT USERS LIKE TOOR!!!!!!
cat /etc/passwd | cut -d ":" -f 1,3 | awk -F ":" '$2 > 1000 {print $1}'