#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (use sudo)."
  exit 1
fi

#reinstall core utilities and services, make backups of important shit before and after
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#reinstall essential config files (like ssh) and binaries 
#binaries IDK IF THESE ARE BINARIES AND THERE ARE DEF MORE YOU SHOULD ADD TO THIS LIST
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
apt install -y --reinstall curl apt-transport-https ca-certificates software-properties-common coreutils openssh-server net-tools build-essential libssl-dev procps lsof tmux nftables jq tar

#install tools that you want/need
apt install -y vim
apt install -y auditd
apt install debsums -y
systemctl enable auditd
systemctl start auditd

#make a hidden directory for backups (the directory name is SYSLOG)
mkdir /var/log/SYSLOG

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











#reinstall docker 111111111111111111111111111111111111111111111111111111111111111111111111111

#Step 1: Stop Docker service
systemctl stop docker
if [[ $? -ne 0 ]]; then
    echo "Failed to stop Docker. Exiting."
    exit 1
fi

# Step 2: Backup Docker data
DOCKER_BACKUP_DIR="/var/log/docker_backup"
mkdir -p "$DOCKER_BACKUP_DIR"
cp -r /var/lib/docker "$DOCKER_BACKUP_DIR"


#container
for container in $(docker ps -aq); do
    CONTAINER_NAME=$(docker inspect --format='{{.Name}}' "$container" | cut -c2-)
    echo "Backing up container: $CONTAINER_NAME"
    docker export "$container" > "$DOCKER_BACKUP_DIR/$CONTAINER_NAME.tar"
    docker inspect "$container" > "$DOCKER_BACKUP_DIR/$CONTAINER_NAME-config.json"
done
#volumes
VOLUME_BACKUP_DIR="$DOCKER_BACKUP_DIR/volumes"
mkdir -p "$VOLUME_BACKUP_DIR"
for volume in $(docker volume ls -q); do
    [ -n "$volume" ] || continue
    echo "Backing up volume: $volume"
    tar -czf "$VOLUME_BACKUP_DIR/$volume.tar.gz" -C "$(docker volume inspect --format '{{ .Mountpoint }}' "$volume")" .
done
#check that backups are there
if [[ $? -ne 0 ]]; then
    echo "Failed to back up Docker data. Exiting."
    exit 1
fi

#delete everything and install from dockers official website
apt remove --purge -y containerd
apt remove --purge -y docker.io containerd containerd.io docker docker-engine docker-ce docker-ce-cli
apt autoremove -y
rm -rf /var/lib/docker /var/lib/containerd


# Step 3: Reinstall Docker
apt update
apt install --reinstall -y docker.io
if [[ $? -ne 0 ]]; then
    echo "Failed to reinstall Docker. Exiting."
    exit 1
fi

#start docker
systemctl start docker

# Step 4: Restore Docker data (ensure no HTTP modifications)

#restore containers
# Restore containers
for container_backup in "$DOCKER_BACKUP_DIR"/*.tar; do
    CONTAINER_NAME=$(basename "$container_backup" .tar)
    CONFIG_FILE="$DOCKER_BACKUP_DIR/$CONTAINER_NAME-config.json"
    
    echo "Restoring container: $CONTAINER_NAME"
    
    # Import the container as an image
    docker import "$container_backup" "${CONTAINER_NAME}_image"

    # Check for configuration file
    if [[ -f "$CONFIG_FILE" ]]; then
        echo "Recreating container: $CONTAINER_NAME with configuration..."
        
        # Extract port bindings
        HOST_PORT=$(jq -r '.HostConfig.PortBindings["80/tcp"][0].HostPort // "80"' "$CONFIG_FILE")
        
        # Extract environment variables
        ENV_VARS=""
        while IFS= read -r env; do
            ENV_VARS+="--env $env "
        done < <(jq -r '.Config.Env[]' "$CONFIG_FILE")

        # Run the container
        docker run -d --name "$CONTAINER_NAME" -p "$HOST_PORT":80 $ENV_VARS "${CONTAINER_NAME}_image"
    else
        echo "Configuration file not found for $CONTAINER_NAME. Using default settings."
        docker run -d --name "$CONTAINER_NAME" -p 80:80 "${CONTAINER_NAME}_image"
    fi
done

#restore volumes
for backup_file in "$VOLUME_BACKUP_DIR"/*.tar.gz; do
    [ -f "$backup_file" ] || continue
    VOLUME_NAME=$(basename "$backup_file" .tar.gz)
    echo "Restoring volume: $VOLUME_NAME"
    docker volume create "$VOLUME_NAME"
    tar -xzf "$backup_file" -C "$(docker volume inspect --format '{{ .Mountpoint }}' "$VOLUME_NAME")"
done


# Step 5: Start Docker service
echo "Starting Docker service..."
systemctl start docker
if [[ $? -ne 0 ]]; then
    echo "Failed to start Docker."
else
    echo "Docker succesfully started"
fi

# Step 6: Verify HTTP service is running
echo "Verifying HTTP service..."
HTTP_PORT=80
docker ps | grep -q "0.0.0.0:$HTTP_PORT->80/tcp"
if [[ $? -eq 0 ]]; then
    echo "HTTP service is running on port $HTTP_PORT."
else
    echo "HTTP service is NOT running. Check Docker container configurations."
fi

#make another backup in your backups
cp -r "$DOCKER_BACKUP_DIR"/* /var/log/SYSLOG/docker











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
#webmin
nft add rule ip filter input tcp dport 10000 accept
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
#webmin
nft add rule ip filter output tcp dport 10000 accept
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

#remove sshd if you want
# systemctl stop sshd
# systemctl disable sshd
# apt remove -y openssh-server

#start ssh for ubuntu box since it is scored
systemctl start ssh
systemctl status ssh

#get webmin
apt install -y wget apt-transport-https software-properties-common
wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -
sh -c 'echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list'
apt install -y webmin --install-recommends

#make a recursive copy of your backups and put it in another location
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#sharads line to make kernel modules require signatures, you need to reboot to get rid of any loaded kernel modules though
sed -i 's/\(vmlinuz.*\)/\1 module.sig_enforce=1 module.sig_unenforce=0/' /boot/grub/grub.cfg

#show bad or altered files
debsums | grep -v 'OK$' 

#show all the users so you can audit them DO NOT DELETE THE CORE ROOT USERS LIKE TOOR!!!!!!
awk -F: '($3 == 0) || ($3 >= 1000 && $3 < 65534) {print $1}' /etc/passwd

