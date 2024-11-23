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



#reinstall real PAM .so's
#backup configs
###mkdir /var/log/SYSLOG/backs_bf_reinstal/pam_confs
###cp -r /etc/pam.d /var/log/SYSLOG/backs_bf_reinstal/pam_confs
#delete .so's and configs
#can't run this either without bricking ur box
#apt purge libpam0g libpam-modules libpam-modules-bin libpam-runtime
# this line will not allow any sudo shells to be opened, none can be opened this will brick your box!!!!
#rm -rf /etc/pam.d/*
#reinstall the package that holds the clean configs for pam.d/
###apt install -y --reinstall libpam-runtime
#reinstall everything
###apt install -y --reinstall libpam0g libpam-modules libpam-modules-bin
#make immutable
###chattr +i /lib/x86_64-linux-gnu/security
###chattr +i /usr/lib/x86_64-linux-gnu/security
###chattr +i /etc/pam.d/*
#copy ssh config before reinstallation
###cp /etc/ssh/sshd_config /var/log/SYSLOG/backs_bf_reinstal/sshd_config.bak


#stop sshd
systemctl stop ssh
systemctl disable ssh

#reinstall essential packages that might be backdoored (this includes their binaries)
#note that this does not reinstall the config files
#THIS WOULD BE A LOT FASTER AND BETTER WITH NALA INSTEAD OF APT
packages=(
  curl 
  apt-transport-https 
  #ca-certificates might affect docker in a bad way
  software-properties-common 
  coreutils 
  openssh-server 
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
  login 
  cron 
  systemd 
  openssh-client 
  mount 
  acl 
  inetutils-ping 
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



#backup docker before reinstallation later on
mkdir -p /var/log/SYSLOG/backs_bf_reinstal/docker_backup
cp -r /etc/docker /var/log/SYSLOG/backs_bf_reinstal/docker_backup

#reinstall docker 

#Step 1: Stop Docker service
systemctl stop docker
systemctl disable docker

if [[ $? -ne 0 ]]; then
    echo "Failed to stop Docker. Exiting."
    exit 1
fi

# Step 2: Backup Docker data
DOCKER_BACKUP_DIR="/var/log/docker_backup"
mkdir -p "$DOCKER_BACKUP_DIR"
cp -r /var/lib/docker "$DOCKER_BACKUP_DIR"

#containers
for container in $(docker ps -aq); do
    CONTAINER_NAME=$(docker inspect --format='{{.Name}}' "$container" | cut -c2-)
    echo "Backing up container: $CONTAINER_NAME"

    # Export container image
    IMAGE_NAME=$(docker inspect --format='{{.Config.Image}}' "$container")
    if ! docker save "$IMAGE_NAME" > "$DOCKER_BACKUP_DIR/$CONTAINER_NAME-image.tar"; then
        echo "Error saving image for container: $CONTAINER_NAME" >&2
        continue
    fi

    # Export container metadata
    if ! docker inspect "$container" | jq '.[0] | {Name: .Name, Config: .Config, HostConfig: .HostConfig, NetworkSettings: .NetworkSettings}' > "$DOCKER_BACKUP_DIR/$CONTAINER_NAME-config.json"; then
        echo "Error exporting config for container: $CONTAINER_NAME" >&2
        continue
    fi
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

#delete everything 
apt remove -y containerd
apt remove -y docker.io containerd containerd.io docker docker-engine docker-ce docker-ce-cli
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
systemctl enable docker

# Step 4: Restore Docker data (ensure no HTTP modifications)

#restore containers
for image_backup in "$DOCKER_BACKUP_DIR"/*-image.tar; do
    # Extract the container name from the backup file
    CONTAINER_NAME=$(basename "$image_backup" -image.tar)
    CONFIG_FILE="$DOCKER_BACKUP_DIR/$CONTAINER_NAME-config.json"

    echo "Restoring container: $CONTAINER_NAME"

    # Load the saved image
    if ! docker load < "$image_backup"; then
        echo "Error loading image for $CONTAINER_NAME" >&2
        continue
    fi

    # Check for the configuration file
    if [[ -f "$CONFIG_FILE" ]]; then
        echo "Recreating container: $CONTAINER_NAME with configuration..."

        # Extract image name from configuration
        IMAGE_NAME=$(jq -r '.Config.Image' "$CONFIG_FILE")

        # Extract port bindings
        PORT_BINDINGS=""
        PORTS=$(jq -r '.HostConfig.PortBindings | keys[]' "$CONFIG_FILE")
        for PORT in $PORTS; do
            HOST_PORT=$(jq -r ".HostConfig.PortBindings[\"$PORT\"][0].HostPort // empty" "$CONFIG_FILE")
            CONTAINER_PORT=$(echo "$PORT" | cut -d/ -f1)
            if [[ -n "$HOST_PORT" ]]; then
                PORT_BINDINGS+=" -p $HOST_PORT:$CONTAINER_PORT"
            fi
        done

        # Extract environment variables
        ENV_VARS=""
        ENV_LIST=$(jq -r '.Config.Env[] // empty' "$CONFIG_FILE")
        for ENV in $ENV_LIST; do
            ENV_VARS+=" --env $ENV"
        done

        # Run the container
        if ! docker run -d --name "$CONTAINER_NAME" $PORT_BINDINGS $ENV_VARS "$IMAGE_NAME"; then
            echo "Error recreating container: $CONTAINER_NAME" >&2
            continue
        fi
    else
        echo "Configuration file not found for $CONTAINER_NAME. Using default settings."

        # Run the container with default settings
        if ! docker run -d --name "$CONTAINER_NAME" "$IMAGE_NAME"; then
            echo "Error recreating container: $CONTAINER_NAME" >&2
            continue
        fi
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
    echo "HTTP service is NOT running or may be on a different port. Check Docker container configurations."
fi

#backup docker after reinstallation
mkdir -p /var/log/SYSLOG/backs_af_reinstal/docker_backup
cp -r /etc/docker /var/log/SYSLOG/backs_af_reinstal/docker_backup



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
nft list ruleset > /etc/nftables.conf
cp /etc/nftables.conf /var/log/SYSLOG/nftables_rules.bak
chattr +i /etc/nftables.conf
#ensure the nftables service loads the rules on boot
systemctl enable nftables



#remove sshd if you want
# systemctl stop sshd
# systemctl disable sshd
# apt remove -y openssh-server



#start ssh for ubuntu box since it is scored
systemctl start ssh
systemctl enable ssh


#get webmin
# echo "deb http://download.webmin.com/download/repository sarge contrib" | tee /etc/apt/sources.list.d/webmin.list
# wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -
# apt update
# sudo apt install -y webmin --install-recommends
# systemctl enable webmin
# systemctl start webmin 
#IDK IF THIS EVEN WORKS BUT WE ARE NOT USING WEBIN SINCE THERE ARE NO GUI'S!!!



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