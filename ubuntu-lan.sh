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
apt install -y --reinstall coreutils openssh-server net-tools build-essential libssl-dev procps lsof tmux nftables

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

#disable firewalld and ufw
systemctl disable --now firewalld
systemctl disable --now ufw

#delete and stop iptables legacy and iptables-nft
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X
iptables -t raw -F
iptables -t raw -X
iptables-legacy -F
iptables-legacy -X
iptables-nft -F
iptables-nft -X
systemctl stop iptables
systemctl disable iptables
systemctl stop iptables-legacy
systemctl disable iptables-legacy
systemctl stop iptables-persistent
systemctl disable iptables-persistent
blacklist ip_tables
blacklist iptable_nat
blacklist ip6_tables
blacklist iptable_mangle
blacklist iptable_raw
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


#setup nftables table input
nft add table ip filter
nft add chain ip filter input { type filter hook input priority 0 \; }
# Allow established and related traffic
nft add rule ip filter input ct state established,related log accept
#allow rules input
#ssh
nft add rule ip filter input tcp dport 22 accept
#docker (HTTP)
nft add rule ip filter input tcp dport 80 accept
#HTTPS
nft add rule ip filter input tcp dport 443 accept
#docker api
nft add rule ip filter input tcp dport 2375 accept
nft add rule ip filter input tcp dport 2376 accept
#drop everything else
nft add rule ip filter input drop



#setup nftables table output
nft add chain ip filter output { type filter hook output priority 0 \; }
nft add rule ip filter output ct state established,related log accept
#allow rules output
#DNS
nft add rule ip filter output udp dport 53 accept
#ssh
nft add rule ip filter output tcp dport 22 accept
#docker (HTTP)
nft add rule ip filter output tcp dport 80 accept
#HTTPS
nft add rule ip filter output tcp dport 443 accept
#docker api
nft add rule ip filter output tcp dport 2375 accept
nft add rule ip filter output tcp dport 2376 accept
#drop all other output
nft add rule ip filter output drop

#save the rules to a file and make it immutable
sudo nft list ruleset > /etc/nftables.conf
chattr +i /etc/nftables.conf
#ensure the nftables service loads the rules on boot
systemctl enable nftables


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
awk -F: '($3 == 0) || ($3 >= 1000 && $3 < 65534) {print $1}' /etc/passwd

