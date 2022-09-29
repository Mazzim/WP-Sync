#!/bin/bash

# wp-sync.sh
#
# Syncing Wordpress dir and DB between prod and dev, local and remote environments
# by Maksim Varfolomeev http://five.pictures/team/maksim-varfolomeev
#
# This script needs a root ssh access to the remote machine and sudo user priveleges.
#
# Assume you have already created SSH key and set up root public key authentication with remote server,
# if you did not, do this first:
# sudo su
# ssh-keygen
# cat ~/.ssh/id_rsa.pub | ssh root@your-remote-server.com "cat >> ~/.ssh/authorized_keys"
# Make sure on the remote machine you have "PermitRootLogin yes" (sudo nano /etc/ssh/sshd_config)
#
# Credits and links
# Re-launching script as root: http://serverfault.com/questions/547923/running-ssh-agent-from-a-shell-script
# Caching SSH key passphrase: http://rabexc.org/posts/pitfalls-of-ssh-agents
# ANSI Escape codes and cursor movements source:
# http://www.tldp.org/HOWTO/Bash-Prompt-HOWTO/x361.html
# http://wiki.bash-hackers.org/scripting/terminalcodes
# Key press trick destinguishing between Enter and Space source:
# http://stackoverflow.com/questions/22842896/bash-scripting-read-single-keystroke-including-special-keys-enter-and-space
#
#
# Define Production and Developer environment domain names below. 
# The script makes some assumptions:
# The same domain name used in the path of WP installation, and is the name of the user and group-owner of the WP directory
# For ex., Production PROD=five.pictures
# The script assumes that WP installation lives in /var/www/five.pictures/public_html and it is owned by five.pictures:five.pictures
# It assumes the local WP installation lives under the same path and with the same ownership (local server is a clone of your main remote server)
# It also assumes you have aroot accsess to remote server and a sudo priveleges on the local one

#################################################
#   Setup: Fill up the following four lines		#
#################################################

PROD=example.com								# Your main remote Production site domain (no http, no trails, just FQDN)

DEV=dev.example.com								# Your remote Developer site domain

LOC_PROD=localhost:8888							# Your local Production site domain

LOC_DEV=dev.localhost:8888						# Your local Developer site domain

################################################# Assumptions

PROD_SERV=$PROD									# This is what script uses when connects to a remote Prod server ( root@$PROD_SERV )
DEV_SERV=$PROD									# My Dev and Prod sites live on the same server. Change to $DEV if you host it separately
												# But then your two servers must have each other's id_rsa.pub keys stored in authorized_keys

REMOTE_WP=/var/www/$PROD/public_html			# Path to Production site WP directory
REMOTE_WP_URL=https://$PROD						# URL and site Home values used inside WP site and the database
DEV_REMOTE_WP=/var/www/$DEV/public_html			# Path to Developer site WP directory
DEV_REMOTE_WP_URL=https://$DEV					# Developer URL and site Home for WP database
LOCAL_WP=$REMOTE_WP								# Assume that local Production copy mirrors the path of your main remote site
LOCAL_WP_URL=https://$LOC_PROD					# URL and site Home used for local Production DB
DEV_LOCAL_WP=$DEV_REMOTE_WP						# Assume that local Developer copy mirrors remote Dev site 
DEV_LOCAL_WP_URL=https://$LOC_DEV				# URL and site Home for local Developer DB

#################################################

# If not run as root, restart script with sudo priveleges
if [ $( id -u ) -ne 0 ]; then
    exec sudo -p "Enter password for %p: " "$0" "$@"
    exit $?
fi

printf 'WP-Sync. Syncs WordPress sites between production/developer, local and remote environments.\n'

# Get Local Prod and Dev DB names, users and passwords from wp-config.php
LOCAL_DB=`grep "DB_NAME" $LOCAL_WP/wp-config.php | cut -f4 -d "'"`
LOCAL_DB_USR=`grep "DB_USER" $LOCAL_WP/wp-config.php | cut -f4 -d "'"`
LOCAL_DB_PWD=`grep "DB_PASSWORD" $LOCAL_WP/wp-config.php | cut -f4 -d "'"`
DEV_LOCAL_DB=`grep "DB_NAME" $DEV_LOCAL_WP/wp-config.php | cut -f4 -d "'"`
DEV_LOCAL_DB_USR=`grep "DB_USER" $DEV_LOCAL_WP/wp-config.php | cut -f4 -d "'"`
DEV_LOCAL_DB_PWD=`grep "DB_PASSWORD" $DEV_LOCAL_WP/wp-config.php | cut -f4 -d "'"`

# Check if SSH key passphrase is already cached, if not, run ssh-agent if needed and cache the passphrase
ssh-add -l &>/dev/null
if [ "$?" == 2 ]; then
	test -r ~/.ssh-agent && \
	eval "$(<~/.ssh-agent)" >/dev/null
	ssh-add -l &>/dev/null
  	if [ $? != 0 ]; then
		(umask 066; ssh-agent > ~/.ssh-agent)
		eval "$(<~/.ssh-agent)" >/dev/null
		ssh-add &>/dev/null
  fi
fi



printf 'Fetching remote server(s) WP database credentials... '

# Get Remote Prod and Dev DB names, users and passwords from corresponding wp-config.php

# comment the following block and use the next Alternative configuration instead
if [ $PROD_SERV=$DEV_SERV ]
then

# Case when Prod and Dev sites live on the same remote server
VARS=($(ssh root@$PROD_SERV "\
							grep 'DB_NAME' $REMOTE_WP/wp-config.php | cut -f4 -d \"'\"; \
							grep 'DB_USER' $REMOTE_WP/wp-config.php | cut -f4 -d \"'\"; \
							grep 'DB_PASSWORD' $REMOTE_WP/wp-config.php | cut -f4 -d \"'\"; \
							grep 'DB_NAME' $DEV_REMOTE_WP/wp-config.php | cut -f4 -d \"'\"; \
							grep 'DB_USER' $DEV_REMOTE_WP/wp-config.php | cut -f4 -d \"'\"; \
							grep 'DB_PASSWORD' $DEV_REMOTE_WP/wp-config.php | cut -f4 -d \"'\""))
REMOTE_DB=${VARS[0]}
REMOTE_DB_USR=${VARS[1]}
REMOTE_DB_PWD=${VARS[2]}
DEV_REMOTE_DB=${VARS[3]}
DEV_REMOTE_DB_USR=${VARS[4]}
DEV_REMOTE_DB_PWD=${VARS[5]}

else

# Alternative configuration if you host your Prod and Dev sites on two separate servers
VARS1=($(ssh root@$PROD_SERV "\
							grep 'DB_NAME' $REMOTE_WP/wp-config.php | cut -f4 -d \"'\"; \
							grep 'DB_USER' $REMOTE_WP/wp-config.php | cut -f4 -d \"'\"; \
							grep 'DB_PASSWORD' $REMOTE_WP/wp-config.php | cut -f4 -d \"'\""))
VARS2=($(ssh root@$DEV_SERV "\
							grep 'DB_NAME' $DEV_REMOTE_WP/wp-config.php | cut -f4 -d \"'\"; \
							grep 'DB_USER' $DEV_REMOTE_WP/wp-config.php | cut -f4 -d \"'\"; \
							grep 'DB_PASSWORD' $DEV_REMOTE_WP/wp-config.php | cut -f4 -d \"'\""))

REMOTE_DB=${VARS1[0]}
REMOTE_DB_USR=${VARS1[1]}
REMOTE_DB_PWD=${VARS1[2]}
DEV_REMOTE_DB=${VARS2[0]}
DEV_REMOTE_DB_USR=${VARS2[1]}
DEV_REMOTE_DB_PWD=${VARS2[2]}

fi

printf '\r\033[K'


while true

do

printf '\n'
read -n1 -rsp $'Sync from [l] local, [r] remote?' key1
case $key1 in

l|L )	#################################### sync from local
	printf '\r'
	read -n1 -rsp $"Local - [p] $LOC_PROD, [d] $LOC_DEV ?" key2
	case $key2 in
	
	p|P )
		printf '\r' 
		printf "Sync $LOC_PROD to"
		read -n1 -rsp $" [p] $PROD, [d] $DEV, [l] $LOC_DEV ?" key3
		case $key3 in

		p|P )
			printf '\r' 
			printf "$LOC_PROD   -->   $PROD     [Enter] to go ahead...\033[K"
			read -d'' -s -n1
			if [ "$REPLY" = $'\x0a' ]						# if [Enter]
			then
				printf "\033[1A"
				printf '\r' 
				printf "Starting...      $LOC_PROD   -->   $PROD\033[K\n"
############ Sync Local Prod  --> Remote Prod

printf 'Syncing WP directory... '
rsync -azhPq --chown=$PROD:$PROD --exclude='wp-config.php' --exclude '.well-known' --delete --force $LOCAL_WP/* root@$PROD_SERV:$REMOTE_WP/

printf '\rSyncing WP database... \033[K'
(mysqldump -u $LOCAL_DB_USR -p$LOCAL_DB_PWD $LOCAL_DB; \
echo "SELECT * FROM wp_options WHERE option_name = \"home\" OR option_name = \"siteurl\"; \
UPDATE wp_options SET option_value=\"${REMOTE_WP_URL}\" WHERE option_name = \"home\" OR option_name = \"siteurl\";") |
ssh -C root@$PROD_SERV mysql -u $REMOTE_DB_USR -p$REMOTE_DB_PWD $REMOTE_DB 1> /dev/null

############
			printf '\rDONE.\033[K'
			else
				printf '\rCancelled.\033[K\n'
			fi
		;;

		d|D )
			printf '\r' 
			printf "$LOC_PROD   -->   $DEV     [Enter] to go ahead...\033[K"
			read -d'' -s -n1
			if [ "$REPLY" = $'\x0a' ] 
			then
				printf "\033[1A"
				printf '\r' 
				printf "Starting...      $LOC_PROD   -->   $DEV\033[K\n"
############ Sync Local Prod  --> Remote Dev

printf 'Syncing WP directory... '
rsync -azhPq --chown=$DEV:$DEV --exclude='wp-config.php' --exclude '.well-known' --delete --force $LOCAL_WP/* root@$DEV_SERV:$DEV_REMOTE_WP/

printf '\rSyncing WP database... \033[K'
(mysqldump -u $LOCAL_DB_USR -p$LOCAL_DB_PWD $LOCAL_DB; \
echo "SELECT * FROM wp_options WHERE option_name = \"home\" OR option_name = \"siteurl\"; \
UPDATE wp_options SET option_value=\"${DEV_REMOTE_WP_URL}\" WHERE option_name = \"home\" OR option_name = \"siteurl\";") |
ssh -C root@$DEV_SERV mysql -u $DEV_REMOTE_DB_USR -p$DEV_REMOTE_DB_PWD $DEV_REMOTE_DB 1> /dev/null

############
			printf '\rDONE.\033[K'
			else
				printf '\rCancelled.\033[K\n'
			fi
		;;

		l|L )
			printf '\r' 
			printf "$LOC_PROD   -->   $LOC_DEV     [Enter] to go ahead...\033[K"
			read -d'' -s -n1
			if [ "$REPLY" = $'\x0a' ] 
			then
				printf "\033[1A"
				printf '\r' 
				printf "Starting...      $LOC_PROD   -->   $LOC_DEV\033[K\n"
############ Sync Local Prod --> Local Dev

printf 'Syncing WP directory... '
rsync -azhPq --chown=$DEV:$DEV --exclude='wp-config.php' --exclude '.well-known' --delete --force $LOCAL_WP/* $DEV_LOCAL_WP/

printf '\rSyncing WP database... \033[K'

(mysqldump -u $LOCAL_DB_USR -p$LOCAL_DB_PWD $LOCAL_DB; \
echo "SELECT * FROM wp_options WHERE option_name = \"home\" OR option_name = \"siteurl\"; \
UPDATE wp_options SET option_value=\"${DEV_LOCAL_WP_URL}\" WHERE option_name = \"home\" OR option_name = \"siteurl\";") |
mysql -u $DEV_LOCAL_DB_USR -p$DEV_LOCAL_DB_PWD $DEV_LOCAL_DB 1> /dev/null

############
			printf '\rDONE.\033[K'
			else
				printf '\rCancelled.\033[K\n'
			fi
		;;
		x|X|q|Q )
			ssh-add -d &>/dev/null									# Remove ssh key passphrase from cache
			printf '\nBye.\n\n'
			exit 1
		;;

		*)
			printf '\n[x] or [q] to exit or choose another sync option...'
		;;
		esac
	;;

	d|D )
		printf '\r' 
		printf "Sync $LOC_DEV to"
		read -n1 -rsp $" [p] $PROD, [d] $DEV, [l] $LOC_PROD ?" key3
		case $key3 in

		p|P )
			printf '\r' 
			printf "$LOC_DEV   -->   $PROD     [Enter] to go ahead...\033[K"
			read -d'' -s -n1
			if [ "$REPLY" = $'\x0a' ] 
			then
				printf "\033[1A"
				printf '\r' 
				printf "Starting...      $LOC_DEV   -->   $PROD\033[K\n"
############ Local Dev --> Remote Prod

printf 'Syncing WP directory... '
rsync -azhPq --chown=$PROD:$PROD --exclude='wp-config.php' --exclude '.well-known' --delete --force $DEV_LOCAL_WP/* root@$PROD_SERV:$REMOTE_WP/

printf '\rSyncing WP database... \033[K'
(mysqldump -u $DEV_LOCAL_DB_USR -p$DEV_LOCAL_DB_PWD $DEV_LOCAL_DB; \
echo "SELECT * FROM wp_options WHERE option_name = \"home\" OR option_name = \"siteurl\"; \
UPDATE wp_options SET option_value=\"${REMOTE_WP_URL}\" WHERE option_name = \"home\" OR option_name = \"siteurl\";") |
ssh -C root@$PROD_SERV mysql -u $REMOTE_DB_USR -p$REMOTE_DB_PWD $REMOTE_DB 1> /dev/null

############
			printf '\rDONE.\033[K'
			else
				printf '\rCancelled.\033[K\n'
			fi
		;;

		d|D )
			printf '\r' 
			printf "$LOC_DEV   -->   $DEV     [Enter] to go ahead...\033[K"
			read -d'' -s -n1
			if [ "$REPLY" = $'\x0a' ] 
			then
				printf "\033[1A"
				printf '\r' 
				printf "Starting...      $LOC_DEV   -->   $DEV\033[K\n"
############ Sync Local Dev --> Remote Dev

printf 'Syncing WP directory... '
rsync -azhPq --chown=$DEV:$DEV --exclude='wp-config.php' --exclude '.well-known' --delete --force $DEV_LOCAL_WP/* root@$DEV_SERV:$DEV_REMOTE_WP/

printf '\rSyncing WP database... \033[K'
(mysqldump -u $DEV_LOCAL_DB_USR -p$DEV_LOCAL_DB_PWD $DEV_LOCAL_DB; \
echo "SELECT * FROM wp_options WHERE option_name = \"home\" OR option_name = \"siteurl\"; \
UPDATE wp_options SET option_value=\"${DEV_REMOTE_WP_URL}\" WHERE option_name = \"home\" OR option_name = \"siteurl\";") |
ssh -C root@$DEV_SERV mysql -u $DEV_REMOTE_DB_USR -p$DEV_REMOTE_DB_PWD $DEV_REMOTE_DB > /dev/null

############
			printf '\rDONE.\033[K'
			else
				printf '\rCancelled.\033[K\n'
			fi
		;;

		l|L )
			printf '\r' 
			printf "$LOC_DEV   -->   $LOC_PROD     [Enter] to go ahead...\033[K"
			read -d'' -s -n1
			if [ "$REPLY" = $'\x0a' ] 
			then
				printf "\033[1A"
				printf '\r' 
				printf "Starting...      $LOC_DEV   -->   $LOC_PROD\033[K\n"
############ Sync Local Dev --> Local Prod

printf 'Syncing WP directory... '
rsync -azhPq --chown=$PROD:$PROD --exclude='wp-config.php' --exclude '.well-known' --delete --force $DEV_LOCAL_WP/* $LOCAL_WP/

printf '\rSyncing WP database... \033[K'
mysqldump -u $DEV_LOCAL_DB_USR -p$DEV_LOCAL_DB_PWD $DEV_LOCAL_DB |
mysql -u $LOCAL_DB_USR -p$LOCAL_DB_PWD $LOCAL_DB << EOF > /dev/null
SELECT * FROM wp_options WHERE option_name = "home" OR option_name = "siteurl";
UPDATE wp_options SET option_value="${LOCAL_WP_URL}" WHERE option_name = "home" OR option_name = "siteurl";
EOF

############
			printf '\rDONE.\033[K'
			else
				printf '\rCancelled.\033[K\n'
			fi
		;;

		x|X|q|Q )
			ssh-add -d &>/dev/null
			printf '\nBye.\n\n'
			exit 1
		;;

		*)
			printf '\n[x] or [q] to exit or choose another sync option...'
		;;
		esac
	;;

	x|X|q|Q )
		ssh-add -d &>/dev/null
		printf '\nBye.\n\n'
		exit 1
	;;

	*)
		printf '\n[x] or [q] to exit or choose another sync option...'
	;;
	esac
;;

r|R )	#################################### sync from remote
	printf '\r'
    read -n1 -rsp $"Remote - [p] $PROD, [d] $DEV ?" key2
	case $key2 in

	p|P )
		printf '\r' 
		printf "Sync $PROD to"
		read -n1 -rsp $" [p] $LOC_PROD, [d] $LOC_DEV, [r] $DEV ?" key3
		case $key3 in
		
		p|P )
			printf '\r' 
			printf "$PROD   -->   $LOC_PROD     [Enter] to go ahead...\033[K"
			read -d'' -s -n1
			if [ "$REPLY" = $'\x0a' ] 
			then
				printf "\033[1A"
				printf '\r' 
				printf "Starting...      $PROD   -->   $LOC_PROD\033[K\n"
############ Sync Remote Prod --> Local Prod

printf 'Syncing WP directory... '
rsync -azhPq --chown=$PROD:$PROD --exclude='wp-config.php' --exclude '.well-known' --delete --force root@$PROD_SERV:$REMOTE_WP/* $LOCAL_WP/

printf '\rSyncing WP database... \033[K'
ssh -C root@$PROD_SERV "mysqldump -u $REMOTE_DB_USR -p$REMOTE_DB_PWD $REMOTE_DB" |
mysql -u $LOCAL_DB_USR -p$LOCAL_DB_PWD $LOCAL_DB 1> /dev/null
echo " \
	SELECT * FROM wp_options WHERE option_name = \"home\" OR option_name = \"siteurl\"; \
	UPDATE wp_options SET option_value=\"${LOCAL_WP_URL}\" WHERE option_name = \"home\" OR option_name = \"siteurl\";" |
mysql -u $LOCAL_DB_USR -p$LOCAL_DB_PWD $LOCAL_DB 1> /dev/null

############
			printf '\rDONE.\033[K'
			else
				printf '\rCancelled.\033[K\n'
			fi
		;;

		d|D )
			printf '\r' 
			printf "$PROD   -->   $LOC_DEV     [Enter] to go ahead...\033[K"
			read -d'' -s -n1
			if [ "$REPLY" = $'\x0a' ] 
			then
				printf "\033[1A"
				printf '\r' 
				printf "Starting...      $PROD   -->   $LOC_DEV\033[K\n"
############ Sync Remote Prod --> Local Dev

printf 'Syncing WP directory... '
rsync -azhPq --chown=$DEV:$DEV --exclude='wp-config.php' --exclude '.well-known' --delete --force root@$PROD_SERV:$REMOTE_WP/* $DEV_LOCAL_WP/

printf '\rSyncing WP database... \033[K'
ssh -C root@$PROD_SERV "mysqldump -u $REMOTE_DB_USR -p$REMOTE_DB_PWD $REMOTE_DB" |
mysql -u $DEV_LOCAL_DB_USR -p$DEV_LOCAL_DB_PWD $DEV_LOCAL_DB 1> /dev/null
echo " \
	SELECT * FROM wp_options WHERE option_name = \"home\" OR option_name = \"siteurl\"; \
	UPDATE wp_options SET option_value=\"${DEV_LOCAL_WP_URL}\" WHERE option_name = \"home\" OR option_name = \"siteurl\";" |
mysql -u $DEV_LOCAL_DB_USR -p$DEV_LOCAL_DB_PWD $DEV_LOCAL_DB 1> /dev/null

############
			printf '\rDONE.\033[K'
			else
				printf '\rCancelled.\033[K\n'
			fi
		;;

		r|R )
			printf '\r' 
			printf "$PROD   -->   $DEV     [Enter] to go ahead...\033[K"
			read -d'' -s -n1
			if [ "$REPLY" = $'\x0a' ] 
			then
				printf "\033[1A"
				printf '\r' 
				printf "Starting...      $PROD   -->   $DEV\033[K\n"
############ Sync Remote Prod --> Remote Dev

printf 'Syncing WP directory and database... '
if [ $PROD_SERV=$DEV_SERV ]
then

ssh root@$PROD_SERV "\
rsync -azhPq --chown=$DEV:$DEV --exclude='wp-config.php' --exclude '.well-known' --delete --force $REMOTE_WP/* $DEV_REMOTE_WP/;\
mysqldump -u $REMOTE_DB_USR -p$REMOTE_DB_PWD $REMOTE_DB |
mysql -u $DEV_REMOTE_DB_USR -p$DEV_REMOTE_DB_PWD $DEV_REMOTE_DB > /dev/null;\
mysql -u $DEV_REMOTE_DB_USR -p$DEV_REMOTE_DB_PWD $DEV_REMOTE_DB << EOF > /dev/null
SELECT * FROM wp_options WHERE option_name = \"home\" OR option_name = \"siteurl\";
UPDATE wp_options SET option_value=\"${DEV_REMOTE_WP_URL}\" WHERE option_name = \"home\" OR option_name = \"siteurl\";
EOF"

else

# Sync between two remote servers. Assume both servers has already ssh keys set up and exchanged.
printf 'Syncing WP directory and database... '
ssh root@$PROD_SERV "\
rsync -azhPq --chown=$DEV:$DEV --exclude='wp-config.php' --exclude '.well-known' --delete --force $REMOTE_WP/* root@$DEV_SERV:$DEV_LOCAL_WP/;\
mysqldump -u $REMOTE_DB_USR -p$REMOTE_DB_PWD $REMOTE_DB |
ssh -C root@$DEV_SERV mysql -u $DEV_REMOTE_DB_USR -p$DEV_REMOTE_DB_PWD $DEV_REMOTE_DB << EOF > /dev/null
SELECT * FROM wp_options WHERE option_name = \"home\" OR option_name = \"siteurl\";
UPDATE wp_options SET option_value=\"${DEV_REMOTE_WP_URL}\" WHERE option_name = \"home\" OR option_name = \"siteurl\";
EOF"

fi

############
			printf '\rDONE.\033[K'
			else
				printf '\rCancelled.\033[K\n'
			fi
		;;


		x|X|q|Q )
			ssh-add -d &>/dev/null
			printf '\nBye.\n\n'
			exit 1
		;;

		*)
			printf '\n[x] or [q] to exit or choose another sync option...'
		;;
		esac
	;;

	d|D )
		printf '\r' 
		printf "Sync $DEV to"
		read -n1 -rsp $" [p] $LOC_PROD, [d] $LOC_DEV, [r] $PROD ?" key3
		case $key3 in

		p|P )
			printf '\r' 
			printf "$DEV   -->   $LOC_PROD     [Enter] to go ahead...\033[K"
			read -d'' -s -n1
			if [ "$REPLY" = $'\x0a' ] 
			then
				printf "\033[1A"
				printf '\r' 
				printf "Starting...      $DEV   -->   $LOC_PROD\033[K\n"
############ Sync Remote Dev --> Local Prod

printf 'Syncing WP directory... '
rsync -azhPq --chown=$PROD:$PROD --exclude='wp-config.php' --exclude '.well-known' --delete --force root@$DEV_SERV:$DEV_REMOTE_WP/* $LOCAL_WP/

printf '\rSyncing WP database... \033[K'
ssh -C root@$DEV_SERV "mysqldump -u $DEV_REMOTE_DB_USR -p$DEV_REMOTE_DB_PWD $DEV_REMOTE_DB" |
mysql -u $LOCAL_DB_USR -p$LOCAL_DB_PWD $LOCAL_DB << EOF > /dev/null
SELECT * FROM wp_options WHERE option_name = "home" OR option_name = "siteurl";
UPDATE wp_options SET option_value="${LOCAL_WP_URL}" WHERE option_name = "home" OR option_name = "siteurl";
EOF

############
			printf '\rDONE.\033[K'
			else
				printf '\rCancelled.\033[K\n'
			fi
		;;

		d|D )
			printf '\r' 
			printf "$DEV   -->   $LOC_DEV     [Enter] to go ahead...\033[K"
			read -d'' -s -n1
			if [ "$REPLY" = $'\x0a' ] 
			then
				printf "\033[1A"
				printf '\r' 
				printf "Starting...      $DEV   -->   $LOC_DEV\033[K\n"
############ Sync Remote Dev --> Local Dev

printf 'Syncing WP directory... '
rsync -azhPq --chown=$DEV:$DEV --exclude='wp-config.php' --exclude '.well-known' --delete --force root@$DEV_SERV:$DEV_REMOTE_WP/* $DEV_LOCAL_WP/

printf '\rSyncing WP database... \033[K'
ssh -C root@$DEV_SERV "mysqldump -u $DEV_REMOTE_DB_USR -p$DEV_REMOTE_DB_PWD $DEV_REMOTE_DB" |
mysql -u $DEV_LOCAL_DB_USR -p$DEV_LOCAL_DB_PWD $DEV_LOCAL_DB << EOF > /dev/null
SELECT * FROM wp_options WHERE option_name = "home" OR option_name = "siteurl";
UPDATE wp_options SET option_value="${DEV_LOCAL_WP_URL}" WHERE option_name = "home" OR option_name = "siteurl";
EOF

############
			printf '\rDONE.\033[K'
			else
				printf '\rCancelled.\033[K\n'
			fi
		;;

		r|R )
			printf '\r' 
			printf "$DEV   -->   $PROD     [Enter] to go ahead...\033[K"
			read -d'' -s -n1
			if [ "$REPLY" = $'\x0a' ] 
			then
				printf "\033[1A"
				printf '\r' 
				printf "Starting...      $DEV   -->   $PROD\033[K\n"
############ Sync Remote Dev --> Remote Prod

printf 'Syncing WP directory and database... '
if [ $PROD_SERV=$DEV_SERV ]
then

ssh root@$DEV_SERV "\
rsync -azhPq --chown=$PROD:$PROD --exclude='wp-config.php' --exclude '.well-known' --delete --force $DEV_REMOTE_WP/* $REMOTE_WP/;\
mysqldump -u $DEV_REMOTE_DB_USR -p$DEV_REMOTE_DB_PWD $DEV_REMOTE_DB |
mysql -u $REMOTE_DB_USR -p$REMOTE_DB_PWD $REMOTE_DB << EOF > /dev/null
SELECT * FROM wp_options WHERE option_name = \"home\" OR option_name = \"siteurl\";
UPDATE wp_options SET option_value=\"${REMOTE_WP_URL}\" WHERE option_name = \"home\" OR option_name = \"siteurl\";
EOF"

else

# Sync between two remote servers. Assume both servers has already ssh keys set up and exchanged.
ssh root@$DEV_SERV "\
rsync -azhPq --chown=$PROD:$PROD --exclude='wp-config.php' --exclude '.well-known' --delete --force $DEV_REMOTE_WP/* root@$PROD_SERV:$LOCAL_WP/;\
mysqldump -u $DEV_REMOTE_DB_USR -p$DEV_REMOTE_DB_PWD $DEV_REMOTE_DB |
ssh -C root@$PROD_SERV mysql -u $REMOTE_DB_USR -p$REMOTE_DB_PWD $REMOTE_DB << EOF > /dev/null
SELECT * FROM wp_options WHERE option_name = \"home\" OR option_name = \"siteurl\";
UPDATE wp_options SET option_value=\"${REMOTE_WP_URL}\" WHERE option_name = \"home\" OR option_name = \"siteurl\";
EOF"

fi

############
			printf '\rDONE.\033[K'
			else
				printf '\rCancelled.\033[K\n'
			fi
		;;

		x|X|q|Q )
			ssh-add -d &>/dev/null
			printf '\nBye.\n\n'
			exit 1
		;;

		*)
			printf '\n[x] or [q] to exit or choose another sync option...'
		;;
		esac
	;;

	x|X|q|Q )
		ssh-add -d &>/dev/null
			printf '\nBye.\n\n'
		exit 1
	;;

	*)
		printf '\n[x] or [q] to exit or choose another sync option...'
	;;
	esac
;;

x|X|q|Q)
	ssh-add -d &>/dev/null
	printf '\nBye.\n\n'
	exit 1
;;

*)
	printf '\n[x] or [q] to exit or choose another sync option...'
;;
esac


done

