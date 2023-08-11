#!/usr/bin/env bash
# shellcheck shell=bash
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
##@Version           :  202305031641-git
# @@Author           :  Jason Hempstead
# @@Contact          :  jason@casjaysdev.pro
# @@License          :  WTFPL
# @@ReadME           :  install.sh --help
# @@Copyright        :  Copyright: (c) 2023 Jason Hempstead, Casjays Developments
# @@Created          :  Wednesday, May 03, 2023 16:41 EDT
# @@File             :  install.sh
# @@Description      :  Container installer script for webvirtmgr
# @@Changelog        :  New script
# @@TODO             :  Completely rewrite/refactor/variable cleanup
# @@Other            :  
# @@Resource         :  
# @@Terminal App     :  no
# @@sudo/root        :  no
# @@Template         :  installers/dockermgr
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# shell check options
# shellcheck disable=SC2317
# shellcheck disable=SC2120
# shellcheck disable=SC2155
# shellcheck disable=SC2199
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
APPNAME="webvirtmgr"
VERSION="202305031641-git"
REPO_BRANCH="${GIT_REPO_BRANCH:-main}"
HOME="${USER_HOME:-$HOME}"
USER="${SUDO_USER:-$USER}"
RUN_USER="${SUDO_USER:-$USER}"
SCRIPT_SRC_DIR="${BASH_SOURCE%/*}"
SCRIPTS_PREFIX="dockermgr"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set bash options
trap 'retVal=$?;trap_exit' ERR EXIT SIGINT
[ "$1" = "--debug" ] && set -x && export SCRIPT_OPTS="--debug" && export _DEBUG="on"
[ "$1" = "--raw" ] && export SHOW_RAW="true"
set -o pipefail
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Import functions
CASJAYSDEVDIR="${CASJAYSDEVDIR:-/usr/local/share/CasjaysDev/scripts}"
SCRIPTSFUNCTDIR="${CASJAYSDEVDIR:-/usr/local/share/CasjaysDev/scripts}/functions"
SCRIPTSFUNCTFILE="${SCRIPTSAPPFUNCTFILE:-mgr-installers.bash}"
SCRIPTSFUNCTURL="${SCRIPTSAPPFUNCTURL:-https://github.com/$SCRIPTS_PREFIX/installer/raw/main/functions}"
connect_test() { curl -q -ILSsf --retry 1 -m 1 "https://1.1.1.1" | grep -iq 'server:*.cloudflare' || return 1; }
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if [ -f "$PWD/$SCRIPTSFUNCTFILE" ]; then
  . "$PWD/$SCRIPTSFUNCTFILE"
elif [ -f "$SCRIPTSFUNCTDIR/$SCRIPTSFUNCTFILE" ]; then
  . "$SCRIPTSFUNCTDIR/$SCRIPTSFUNCTFILE"
elif connect_test; then
  curl -q -LSsf "$SCRIPTSFUNCTURL/$SCRIPTSFUNCTFILE" -o "/tmp/$SCRIPTSFUNCTFILE" || exit 1
  . "/tmp/$SCRIPTSFUNCTFILE"
else
  echo "Can not load the functions file: $SCRIPTSFUNCTDIR/$SCRIPTSFUNCTFILE" 1>&2
  exit 90
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Make sure the scripts repo is installed
scripts_check
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Repository variables
REPO="${DOCKERMGRREPO:-https://github.com/$SCRIPTS_PREFIX}/webvirtmgr"
APPVERSION="$(__appversion "$REPO/raw/$REPO_BRANCH/version.txt")"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Defaults variables
APPNAME="webvirtmgr"
export INSTDIR="$HOME/.local/share/CasjaysDev/$SCRIPTS_PREFIX/webvirtmgr"
export DOCKERMGR_CONFIG_DIR="${DOCKERMGR_CONFIG_DIR:-$HOME/.config/myscripts/$SCRIPTS_PREFIX}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the mountpoint directory
export APPDIR="$HOME/.local/share/srv/docker/webvirtmgr"
export DATADIR="$APPDIR/rootfs"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Call the main function
dockermgr_install
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Script options IE: --help
show_optvars "$@"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# trap the cleanup function
trap_exit
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Require a certain version
dockermgr_req_version "$APPVERSION"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Custom required functions
__sudo_root() { [ "$DOCKERMGR_USER_CAN_SUDO" = "true" ] && sudo "$@" || { [ "$USER" = "root" ] && eval "$*"; } || eval "$*" 2>/dev/null || return 1; }
__sudo_exec() { [ "$DOCKERMGR_USER_CAN_SUDO" = "true" ] && sudo -HE "$@" || { [ "$USER" = "root" ] && eval "$*"; } || eval "$*" 2>/dev/null || return 1; }
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
__remove_extra_spaces() { sed 's/\( \)*/\1/g;s|^ ||g'; }
__port() { echo "$((50000 + $RANDOM % 1000))" | grep '^' || return 1; }
__docker_check() { [ -n "$(type -p docker 2>/dev/null)" ] || return 1; }
__password() { cat "/dev/urandom" | tr -dc '0-9a-zA-Z' | head -c${1:-16} && echo ""; }
__docker_ps_all() { docker ps -a 2>&1 | grep ${1:-} "$CONTAINER_NAME" && return 0 || return 1; }
__enable_ssl() { { [ "$SSL_ENABLED" = "yes" ] || [ "$SSL_ENABLED" = "true" ]; } && return 0 || return 1; }
__docker_is_running() { ps aux 2>/dev/null | grep 'dockerd' | grep -v ' grep ' | grep -q '^' || return 1; }
__ssl_certs() { [ -f "$HOST_SSL_CA" ] && [ -f "$HOST_SSL_CRT" ] && [ -f "$HOST_SSL_KEY" ] && return 0 || return 1; }
__is_server() { echo "${SET_HOST_FULL_NAME:-$HOSTNAME}" | grep -q '^server\..*\..*[a-zA-Z0-9][a-zA-Z0-9]$' || return 1; }
__host_name() { hostname -f 2>/dev/null | grep -F '.' | grep '^' || hostname -f 2>/dev/null | grep '^' || echo "$HOSTNAME"; }
__container_is_running() { docker ps 2>&1 | grep "$CONTAINER_NAME" | grep -qi 'ago.* Up.* [0-9].* ' && return 0 || return 1; }
__container_name() { echo "$HUB_IMAGE_URL-${HUB_IMAGE_TAG:-latest}" | awk -F '/' '{print $(NF-1)"-"$NF}' | grep '^' || return 1; }
__docker_init() { [ -n "$(type -p dockermgr 2>/dev/null)" ] && dockermgr init || printf_exit "Failed to Initialize the docker installer"; }
__domain_name() { hostname -f 2>/dev/null | awk -F '.' '{print $(NF-1)"."$NF}' | grep '\.' | grep '^' || hostname -f 2>/dev/null | grep '^' || return 1; }
__port_in_use() { { [ -d "/etc/nginx/vhosts.d" ] && grep -wRsq "${1:-443}" "/etc/nginx/vhosts.d" || __netstat | grep -q "${1:-443}"; } && return 1 || return 0; }
__netstat() { netstat -taupln 2>/dev/null | grep -vE 'WAIT|ESTABLISHED|docker-pro' | awk -F ' ' '{print $4}' | sed 's|.*:||g' | grep -E '[0-9]' | sort -Vu | grep "^${1:-.*}$" || return 1; }
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
__public_ip() { curl -q -LSsf "http://ifconfig.co" | grep -v '^$' | head -n1 | grep '^'; }
__ifconfig() { [ -n "$(type -P ifconfig)" ] && eval ifconfig "$*" 2>/dev/null || return 1; }
__docker_net_ls() { docker network ls 2>&1 | grep -v 'NETWORK ID' | awk -F ' ' '{print $2}'; }
__route() { [ -n "$(type -P ip)" ] && eval ip route 2>/dev/null | grep "${1:-default}" | grep -v '^$' | head -n1 || return 1; }
__is_private_ip() { grep -E '192\.168\.[0-255]\.[0-255]|10\.[0-255]\.[0-255]\.[0-255]|172\.[10-32]|172\.[10-15]' 2>/dev/null | grep -vE '127\.[0-255]\.[0-255]\.[0-255]|172\.17'; }
__docker_gateway_ip() { sudo docker network inspect -f '{{json .IPAM.Config}}' ${HOST_DOCKER_NETWORK:-bridge} 2>/dev/null | jq -r '.[].Gateway' | grep -Ev '^$|null' | head -n1 | grep '^' || return 1; }
__docker_net_create() { __docker_net_ls | grep -q "$HOST_DOCKER_NETWORK" && return 0 || { docker network create -d bridge --attachable $HOST_DOCKER_NETWORK &>/dev/null && __docker_net_ls | grep -q "$HOST_DOCKER_NETWORK" && echo "$HOST_DOCKER_NETWORK" && return 0 || return 1; }; }
__local_lan_ip() { __ifconfig $SET_LAN_DEV | grep -w 'inet' | awk -F ' ' '{print $2}' | __is_private_ip | head -n1 | grep '^' || ip address show $SET_LAN_DEV 2>&1 | grep 'inet ' | awk -F ' ' '{print $2}' | sed 's|/.*||g' | __is_private_ip | grep -v '^$' | head -n1 | grep '^' || echo "$CURRENT_IP_4" | grep '^' || return 1; }
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Ensure docker is installed and running
__docker_check || __docker_init
__docker_is_running || printf_exit "Docker is not running"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Define any pre-install scripts
__run_pre_install() {

  return 0
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Define any post-install scripts
run_post_install() {

  return 0
}
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
__show_post_message() {

  return 0
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup application options
setopts=$(getopt -o "e:,m:,p:,h:,d:" --long "options,env:,mount:,port:,host:,domain:" -n "$APPNAME" -- "$@" 2>/dev/null)
set -- "${setopts[@]}" 2>/dev/null
while :; do
  case "$1" in
  -h | --host) CONTAINER_OPT_HOSTNAME="$2" && shift 2 ;;
  -d | --domain) CONTAINER_OPT_DOMAINNAME="$2" && shift 2 ;;
  -e | --env) CONTAINER_OPT_ENV_VAR="$2 $CONTAINER_OPT_ENV_VAR" && shift 2 ;;
  -m | --mount) CONTAINER_OPT_MOUNT_VAR="$2 $CONTAINER_OPT_ENV_VAR" && shift 2 ;;
  -p | --port) CONTAINER_OPT_PORT_VAR="$2 $CONTAINER_OPT_PORT_VAR" && shift 2 ;;
  --options) shift 1 && echo "Options: -e -p -h -d --options --env --port --host --domain" && exit 1 ;;
  *) break ;;
  esac
done
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[ -n "$(type -P sudo)" ] && sudo -n true && sudo true && DOCKERMGR_USER_CAN_SUDO="true"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup networking
SET_LAN_DEV=$(__route | sed -e "s/^.*dev.//" -e "s/.proto.*//" | awk '{print $1}' | grep '^' || echo 'eth0')
SET_DOCKER_IP="$(__docker_gateway_ip || echo '172.17.0.1')"
SET_LAN_IP=$(__local_lan_ip || echo '127.0.0.1')
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# get variables from env
ENV_HOSTNAME="${ENV_HOSTNAME:-$SET_HOSTNAME}"
ENV_DOMAINNAME="${ENV_DOMAINNAME:-$SET_DOMAIN}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# get variables from host
SET_LOCAL_HOSTNAME=$(__host_name)
SET_LONG_HOSTNAME=$(hostname -f 2>/dev/null | grep '^')
SET_SHORT_HOSTNAME=$(hostname -s 2>/dev/null | grep '^')
SET_DOMAIN_NAME=$(__domain_name || hostname -d 2>/dev/null | grep -F '.' | grep '^' || echo 'home')
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set hostname and domain
SET_HOST_FULL_NAME="${FULL_HOST:-$SET_LONG_HOSTNAME}"
SET_HOST_FULL_DOMAIN="${FULL_DOMAIN:-$SET_DOMAIN_NAME}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Define folders
HOST_DATA_DIR="$DATADIR/data"
HOST_CONFIG_DIR="$DATADIR/config"
LOCAL_DATA_DIR="${LOCAL_DATA_DIR:-$HOST_DATA_DIR}"
LOCAL_CONFIG_DIR="${LOCAL_CONFIG_DIR:-$HOST_CONFIG_DIR}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# SSL Setup server mounts - [/etc/ssl/CA/certs/ca.crt] [/etc/ssl/CA/certs/host.crt] [/etc/ssl/CA/certs/host.key]
HOST_SSL_CA=""
HOST_SSL_CRT=""
HOST_SSL_KEY=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# SSL Setup container mounts - [/config/ssl/ca.crt] [/config/ssl/localhost.crt] [/config/ssl/localhost.key]
CONTAINER_SSL_CA=""
CONTAINER_SSL_CRT=""
CONTAINER_SSL_KEY=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# URL to container image - docker pull - [URL]
HUB_IMAGE_URL="casjaysdevdocker/webvirtmgr"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# image tag - [docker pull HUB_IMAGE_URL:tag]
HUB_IMAGE_TAG="latest"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the container name Default: [org-repo-tag]
CONTAINER_NAME=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set this if the container depend on external file/app
CONTAINER_REQUIRES=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set container timezone - Default: [America/New_York]
CONTAINER_TIMEZONE=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the working dir - [/root]
CONTAINER_WORK_DIR=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the html dir - [/data/www/html] [WWW_ROOT_DIR]
CONTAINER_HTML_DIR=""
CONTAINER_HTML_ENV=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set container user and group ID - [yes/no] [id] [id]
USER_ID_ENABLED="no"
CONTAINER_USER_ID=""
CONTAINER_GROUP_ID=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set runas user - default root - [mysql]
CONTAINER_USER_RUN=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Enable privileged container - [ yes/no ]
CONTAINER_PRIVILEGED_ENABLED="yes"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the SHM Size - Default: 64M - [128M]
CONTAINER_SHM_SIZE="128M"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the RAM Size in Megs - [1024]
CONTAINER_RAM_SIZE=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the SWAP Size in Megs - [512]
CONTAINER_SWAP_SIZE=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the number of cpus - [2]
CONTAINER_CPU_COUNT="2"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Restart container - [no/always/on-failure/unless-stopped]
CONTAINER_AUTO_RESTART="always"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Delete container after exit - [yes/no]
CONTAINER_AUTO_DELETE="no"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Enable tty and interactive - [yes/no]
CONTAINER_TTY_ENABLED="yes"
CONTAINER_INTERACTIVE_ENABLED="no"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# create an env file - [yes/no] [/config/.env]
CONTAINER_ENV_FILE_ENABLED="no"
CONTAINER_ENV_FILE_MOUNT=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Enable cgroups - [yes/no] [/sys/fs/cgroup]
CGROUPS_ENABLED="no"
CGROUPS_MOUNTS=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set location to resolv.conf - [yes/no] [/etc/resolv.conf]
HOST_RESOLVE_ENABLED="no"
HOST_ETC_RESOLVE_INIT_FILE=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Enable hosts /etc/hosts file - [yes/no] [/etc/hosts]
HOST_ETC_HOSTS_ENABLED="yes"
HOST_ETC_HOSTS_INIT_FILE=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Mount docker socket - [yes/no] [/var/run/docker.sock]
DOCKER_SOCKET_ENABLED="no"
DOCKER_SOCKET_MOUNT=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Mount docker config - [yes/no] [~/.docker/config.json] [/root/.docker/config.json]
DOCKER_CONFIG_ENABLED="no"
HOST_DOCKER_CONFIG=""
CONTAINER_DOCKER_CONFIG_FILE=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Mount soundcard - [yes/no] [/dev/snd] [/dev/snd]
DOCKER_SOUND_ENABLED="no"
HOST_SOUND_DEVICE="/dev/snd"
CONTAINER_SOUND_DEVICE_FILE="/dev/snd"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Enable display in container - [yes/no] [0] [/tmp/.X11-unix] [~/.Xauthority]
CONTAINER_X11_ENABLED="no"
HOST_X11_DISPLAY=""
HOST_X11_SOCKET=""
HOST_X11_XAUTH=""
CONTAINER_X11_SOCKET="/tmp/.X11-unix"
CONTAINER_X11_XAUTH="/home/x11user/.Xauthority"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set container hostname and domain - Default: [webvirtmgr.$SET_HOST_FULL_NAME] [$SET_HOST_FULL_DOMAIN]
CONTAINER_HOSTNAME=""
CONTAINER_DOMAINNAME=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the network type - default is bridge - [bridge/host]
HOST_DOCKER_NETWORK="bridge"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Link to an existing container - [name:alias,name]
HOST_DOCKER_LINK=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set listen type - Default all - [all/local/lan/docker/public]
HOST_NETWORK_ADDR="all"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set this to the protocol the the container will use - [http/https/git/ftp/pgsql/mysql/mongodb]
CONTAINER_PROTOCOL="http"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set containers dns [127.0.0.1,1.1.1.1,8.8.8.8]
CONTAINER_DNS=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup nginx proxy variables - [yes/no] [yes/no] [http] [https] [yes/no]
HOST_NGINX_ENABLED="yes"
HOST_NGINX_SSL_ENABLED="yes"
HOST_NGINX_HTTP_PORT="80"
HOST_NGINX_HTTPS_PORT="443"
HOST_NGINX_UPDATE_CONF="yes"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Enable this if container is running a webserver - [yes/no] [internalPort] [yes/no] [yes/no] [listen]
CONTAINER_WEB_SERVER_ENABLED="no"
CONTAINER_WEB_SERVER_INT_PORT="80"
CONTAINER_WEB_SERVER_SSL_ENABLED="no"
CONTAINER_WEB_SERVER_AUTH_ENABLED="no"
CONTAINER_WEB_SERVER_LISTEN_ON="127.0.0.10"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Specify custom nginx vhosts - autoconfigure: [*./name.all/name.mydomain/name.myhostname] - [virtualhost,othervhostdom]
CONTAINER_WEB_SERVER_VHOSTS=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Add random portmapping - [port,otherport] or [proxy|/location|port]
CONTAINER_ADD_RANDOM_PORTS=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Add custom port -  [exter:inter] or [listen:exter:inter/[tcp,udp]] random:[inter]
CONTAINER_ADD_CUSTOM_PORT=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# mail settings - [yes/no] [user] [domainname] [server]
CONTAINER_EMAIL_ENABLED=""
CONTAINER_EMAIL_USER=""
CONTAINER_EMAIL_DOMAIN=""
CONTAINER_EMAIL_RELAY=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Easy setup for services - [no/yes]
CONTAINER_SERVICE_PUBLIC="yes"
CONTAINER_IS_DNS_SERVER="no"
CONTAINER_IS_DHCP_SERVER="no"
CONTAINER_IS_TFTP_SERVER="no"
CONTAINER_IS_SMTP_SERVER="no"
CONTAINER_IS_POP3_SERVER="no"
CONTAINER_IS_IMAP_SERVER="no"
CONTAINER_IS_TIME_SERVER="no"
CONTAINER_IS_NEWS_SERVER="no"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Database settings - [listen] [yes/no]
CONTAINER_DATABASE_LISTEN=""
CONTAINER_REDIS_ENABLED=""
CONTAINER_SQLITE3_ENABLED=""
CONTAINER_MARIADB_ENABLED=""
CONTAINER_MONGODB_ENABLED=""
CONTAINER_COUCHDB_ENABLED=""
CONTAINER_POSTGRES_ENABLED=""
CONTAINER_SUPABASE_ENABLED=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Custom database setup - [yes/no] [mysql] [port/directory] [/data/db/$CONTAINER_CUSTOM_DATABASE_NAME] [msql]
CONTAINER_CUSTOM_DATABASE_ENABLED=""
CONTAINER_CUSTOM_DATABASE_NAME=""
CONTAINER_CUSTOM_DATABASE_PORT=""
CONTAINER_CUSTOM_DATABASE_DIR=""
CONTAINER_CUSTOM_DATABASE_PROTOCOL=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Database root user - [user] [pass/random]
CONTAINER_DATABASE_USER_ROOT=""
CONTAINER_DATABASE_PASS_ROOT=""
CONTAINER_DATABASE_LENGTH_ROOT="20"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Database non-root user - [user] [pass/random]
CONTAINER_DATABASE_USER_NORMAL=""
CONTAINER_DATABASE_PASS_NORMAL=""
CONTAINER_DATABASE_LENGTH_NORMAL="20"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set a username and password - [user] [pass/random]
CONTAINER_USER_NAME=""
CONTAINER_USER_PASS=""
CONTAINER_PASS_LENGTH="24"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set container username and password env name - [CONTAINER_ENV_USER_NAME=$CONTAINER_USER_NAME]
CONTAINER_ENV_USER_NAME=""
CONTAINER_ENV_PASS_NAME=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Add the names of processes - [apache,mysql]
CONTAINER_SERVICES_LIST=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Mount container data dir - [yes/no] [/data]
CONTAINER_MOUNT_DATA_ENABLED="yes"
CONTAINER_MOUNT_DATA_MOUNT_DIR=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Mount container config dir - [yes/no] [/config]
CONTAINER_MOUNT_CONFIG_ENABLED="yes"
CONTAINER_MOUNT_CONFIG_MOUNT_DIR=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Define additional mounts - [/dir:/dir,/otherdir:/otherdir]
CONTAINER_MOUNTS=""
CONTAINER_MOUNTS+=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Define additional devices - [/dev:/dev,/otherdev:/otherdev]
CONTAINER_DEVICES=""
CONTAINER_DEVICES+=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Define additional variables - [myvar=var,myothervar=othervar]
CONTAINER_ENV=""
CONTAINER_ENV+=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set sysctl - []
CONTAINER_SYSCTL=""
CONTAINER_SYSCTL+=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set capabilites - [yes/no]
DOCKER_SYS_TIME="yes"
DOCKER_SYS_ADMIN="yes"
DOCKER_CAP_CHOWN="no"
DOCKER_CAP_NET_RAW="no"
DOCKER_CAP_SYS_NICE="no"
DOCKER_CAP_NET_ADMIN="no"
DOCKER_CAP_NET_BIND_SERVICE="no"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Define labels - [traefik.enable=true,label=label,otherlabel=label2]
CONTAINER_LABELS=""
CONTAINER_LABELS+=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Specify container arguments - will run in container - [/path/to/script]
CONTAINER_COMMANDS=""
CONTAINER_COMMANDS+=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Define additional docker arguments - see docker run --help - [--option arg1,--option2]
DOCKER_CUSTOM_ARGUMENTS=""
DOCKER_CUSTOM_ARGUMENTS+=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Enable debugging - [yes/no] [Eex]
CONTAINER_DEBUG_ENABLED="no"
CONTAINER_DEBUG_OPTIONS=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# additional directories to create - [/config/dir1,/data/dir2]
CONTAINER_CREATE_DIRECTORY="/data/$APPNAME,/config/$APPNAME,"
CONTAINER_CREATE_DIRECTORY+=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Show post install message
POST_SHOW_FINISHED_MESSAGE=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Run the script if it exists [yes/no]
DOCKERMGR_ENABLE_INSTALL_SCRIPT="yes"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set custom container enviroment variables - [--env MYVAR="VAR"]
__custom_docker_env() {
  cat <<EOF | tee | sed 's|,| --env |g' | tr '\n' ' ' | __remove_extra_spaces

EOF
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# this function will create an env file in the containers filesystem - see CONTAINER_ENV_FILE_ENABLED
__container_import_variables() {
  [ "$CONTAINER_ENV_FILE_ENABLED" = "yes" ] || return 0
  local base_dir="" base_file="$1"
  base_dir="$(realpath "$DATADIR")/$(dirname "$base_file")"
  [ -d "$base_dir" ] || mkdir -p "$base_dir"
  cat <<EOF | __remove_extra_spaces | tee "$base_dir/$base_file" &>/dev/null

EOF
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
__dockermgr_variables() {
  [ -d "$DOCKERMGR_CONFIG_DIR/env" ] || mkdir -p "$DOCKERMGR_CONFIG_DIR/env"
  cat <<EOF | tee | tr '|' '\n' | __remove_extra_spaces
# Enviroment variables for $APPNAME
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
HOST_DATA_DIR="\${ENV_HOST_DATA_DIR:-$HOST_DATA_DIR}"
HOST_CONFIG_DIR="\${ENV_HOST_CONFIG_DIR:-$HOST_CONFIG_DIR}"
HOST_SSL_DIR="\${ENV_HOST_SSL_DIR:-$HOST_SSL_DIR}"
HOST_SSL_CA="\${ENV_HOST_SSL_CA:-$HOST_SSL_CA}"
HOST_SSL_CRT="\${ENV_HOST_SSL_CRT:-$HOST_SSL_CRT}"
HOST_SSL_KEY="\${ENV_HOST_SSL_KEY:-$HOST_SSL_KEY}"
HOST_RESOLVE_ENABLED="\${ENV_HOST_RESOLVE_ENABLED:-$HOST_RESOLVE_ENABLED}"
HOST_RESOLVE_FILE="\${ENV_HOST_RESOLVE_FILE:-$HOST_RESOLVE_FILE}"
HOST_ETC_HOSTS_ENABLED="\${ENV_HOST_ETC_HOSTS_ENABLED:-$HOST_ETC_HOSTS_ENABLED}"
HOST_ETC_HOSTS_MOUNT="\${ENV_HOST_ETC_HOSTS_MOUNT:-$HOST_ETC_HOSTS_MOUNT}"
HOST_DOCKER_CONFIG="\${ENV_HOST_DOCKER_CONFIG:-$HOST_DOCKER_CONFIG}"
HOST_SOUND_DEVICE="\${ENV_HOST_SOUND_DEVICE:-$HOST_SOUND_DEVICE}"
HOST_X11_DISPLAY="\${ENV_HOST_X11_DISPLAY:-$HOST_X11_DISPLAY}"
HOST_X11_SOCKET="\${ENV_HOST_X11_SOCKET:-$HOST_X11_SOCKET}"
HOST_X11_XAUTH="\${ENV_HOST_X11_XAUTH:-$HOST_X11_XAUTH}"
HOST_DOCKER_NETWORK="\${ENV_HOST_DOCKER_NETWORK:-$HOST_DOCKER_NETWORK}"
HOST_DOCKER_LINK="\${ENV_HOST_DOCKER_LINK:-$HOST_DOCKER_LINK}"
HOST_NETWORK_ADDR="\${ENV_HOST_NETWORK_ADDR:-$HOST_NETWORK_ADDR}"
HOST_NGINX_ENABLED="\${ENV_HOST_NGINX_ENABLED:-$HOST_NGINX_ENABLED}"
HOST_NGINX_SSL_ENABLED="\${ENV_HOST_NGINX_SSL_ENABLED:-$HOST_NGINX_SSL_ENABLED}"
HOST_NGINX_HTTP_PORT="\${ENV_HOST_NGINX_HTTP_PORT:-$HOST_NGINX_HTTP_PORT}"
HOST_NGINX_HTTPS_PORT="\${ENV_HOST_NGINX_HTTPS_PORT:-$HOST_NGINX_HTTPS_PORT}"
HOST_NGINX_UPDATE_CONF="\${ENV_HOST_NGINX_UPDATE_CONF:-$HOST_NGINX_UPDATE_CONF}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
CONTAINER_SSL_CA="${CONTAINER_SSL_CA:-}"
CONTAINER_SSL_CRT="${CONTAINER_SSL_CRT:-}"
CONTAINER_SSL_KEY="${CONTAINER_SSL_KEY:-}"
CONTAINER_NAME="${CONTAINER_NAME:-}"
CONTAINER_REQUIRES="${CONTAINER_REQUIRES:-}"
CONTAINER_TIMEZONE="${CONTAINER_TIMEZONE:-}"
CONTAINER_WORK_DIR="${CONTAINER_WORK_DIR:-}"
CONTAINER_HTML_DIR="${CONTAINER_HTML_DIR:-}"
CONTAINER_HTML_ENV="${CONTAINER_HTML_ENV:-}"
CONTAINER_USER_ID="${CONTAINER_USER_ID:-}"
CONTAINER_GROUP_ID="${CONTAINER_GROUP_ID:-}"
CONTAINER_USER_RUN="${CONTAINER_USER_RUN:-}"
CONTAINER_PRIVILEGED_ENABLED="${CONTAINER_PRIVILEGED_ENABLED:-}"
CONTAINER_SHM_SIZE="${CONTAINER_SHM_SIZE:-}"
CONTAINER_RAM_SIZE="${CONTAINER_RAM_SIZE:-}"
CONTAINER_SWAP_SIZE="${CONTAINER_SWAP_SIZE:-}"
CONTAINER_CPU_COUNT="${CONTAINER_CPU_COUNT:-}"
CONTAINER_AUTO_RESTART="${CONTAINER_AUTO_RESTART:-}"
CONTAINER_AUTO_DELETE="${CONTAINER_AUTO_DELETE:-}"
CONTAINER_TTY_ENABLED="${CONTAINER_TTY_ENABLED:-}"
CONTAINER_INTERACTIVE_ENABLED="${CONTAINER_INTERACTIVE_ENABLED:-}"
CONTAINER_ENV_FILE_ENABLED="${CONTAINER_ENV_FILE_ENABLED:-}"
CONTAINER_ENV_FILE_MOUNT="${CONTAINER_ENV_FILE_MOUNT:-}"
CONTAINER_DOCKER_CONFIG_FILE="${CONTAINER_DOCKER_CONFIG_FILE:-}"
CONTAINER_SOUND_DEVICE_FILE="${CONTAINER_SOUND_DEVICE_FILE:-}"
CONTAINER_X11_ENABLED="${CONTAINER_X11_ENABLED:-}"
CONTAINER_X11_SOCKET="${CONTAINER_X11_SOCKET:-}"
CONTAINER_X11_XAUTH="${CONTAINER_X11_XAUTH:-}"
CONTAINER_HOSTNAME="${CONTAINER_HOSTNAME:-}"
CONTAINER_DOMAINNAME="${CONTAINER_DOMAINNAME:-}"
CONTAINER_PROTOCOL="${CONTAINER_PROTOCOL:-}"
CONTAINER_DNS="${CONTAINER_DNS:-}"
CONTAINER_WEB_SERVER_ENABLED="${CONTAINER_WEB_SERVER_ENABLED:-}"
CONTAINER_WEB_SERVER_INT_PORT="${CONTAINER_WEB_SERVER_INT_PORT:-}"
CONTAINER_WEB_SERVER_SSL_ENABLED="${CONTAINER_WEB_SERVER_SSL_ENABLED:-}"
CONTAINER_WEB_SERVER_AUTH_ENABLED="${CONTAINER_WEB_SERVER_AUTH_ENABLED:-}"
CONTAINER_WEB_SERVER_LISTEN_ON="${CONTAINER_WEB_SERVER_LISTEN_ON:-}"
CONTAINER_WEB_SERVER_VHOSTS="${CONTAINER_WEB_SERVER_VHOSTS:-}"
CONTAINER_ADD_RANDOM_PORTS="${CONTAINER_ADD_RANDOM_PORTS:-}"
CONTAINER_ADD_CUSTOM_PORT="${CONTAINER_ADD_CUSTOM_PORT:-}"
CONTAINER_EMAIL_ENABLED="${CONTAINER_EMAIL_ENABLED:-}"
CONTAINER_EMAIL_USER="${CONTAINER_EMAIL_USER:-}"
CONTAINER_EMAIL_DOMAIN="${CONTAINER_EMAIL_DOMAIN:-}"
CONTAINER_EMAIL_RELAY="${CONTAINER_EMAIL_RELAY:-}"
CONTAINER_SERVICE_PUBLIC="${CONTAINER_SERVICE_PUBLIC:-}"
CONTAINER_IS_DNS_SERVER="${CONTAINER_IS_DNS_SERVER:-}"
CONTAINER_IS_DHCP_SERVER="${CONTAINER_IS_DHCP_SERVER:-}"
CONTAINER_IS_TFTP_SERVER="${CONTAINER_IS_TFTP_SERVER:-}"
CONTAINER_IS_SMTP_SERVER="${CONTAINER_IS_SMTP_SERVER:-}"
CONTAINER_IS_POP3_SERVER="${CONTAINER_IS_POP3_SERVER:-}"
CONTAINER_IS_IMAP_SERVER="${CONTAINER_IS_IMAP_SERVER:-}"
CONTAINER_IS_TIME_SERVER="${CONTAINER_IS_TIME_SERVER:-}"
CONTAINER_IS_NEWS_SERVER="${CONTAINER_IS_NEWS_SERVER:-}"
CONTAINER_DATABASE_LISTEN="${CONTAINER_DATABASE_LISTEN:-}"
CONTAINER_REDIS_ENABLED="${CONTAINER_REDIS_ENABLED:-}"
CONTAINER_SQLITE3_ENABLED="${CONTAINER_SQLITE3_ENABLED:-}"
CONTAINER_MARIADB_ENABLED="${CONTAINER_MARIADB_ENABLED:-}"
CONTAINER_MONGODB_ENABLED="${CONTAINER_MONGODB_ENABLED:-}"
CONTAINER_COUCHDB_ENABLED="${CONTAINER_COUCHDB_ENABLED:-}"
CONTAINER_POSTGRES_ENABLED="${CONTAINER_POSTGRES_ENABLED:-}"
CONTAINER_SUPABASE_ENABLED="${CONTAINER_SUPABASE_ENABLED:-}"
CONTAINER_CUSTOM_DATABASE_ENABLED="${CONTAINER_CUSTOM_DATABASE_ENABLED:-}"
CONTAINER_CUSTOM_DATABASE_NAME="${CONTAINER_CUSTOM_DATABASE_NAME:-}"
CONTAINER_CUSTOM_DATABASE_PORT="${CONTAINER_CUSTOM_DATABASE_PORT:-}"
CONTAINER_CUSTOM_DATABASE_DIR="${CONTAINER_CUSTOM_DATABASE_DIR:-}"
CONTAINER_CUSTOM_DATABASE_PROTOCOL="${CONTAINER_CUSTOM_DATABASE_PROTOCOL:-}"
CONTAINER_DATABASE_USER_ROOT="${CONTAINER_DATABASE_USER_ROOT:-}"
CONTAINER_DATABASE_PASS_ROOT="${CONTAINER_DATABASE_PASS_ROOT:-}"
CONTAINER_DATABASE_LENGTH_ROOT="${CONTAINER_DATABASE_LENGTH_ROOT:-}"
CONTAINER_DATABASE_USER_NORMAL="${CONTAINER_DATABASE_USER_NORMAL:-}"
CONTAINER_DATABASE_PASS_NORMAL="${CONTAINER_DATABASE_PASS_NORMAL:-}"
CONTAINER_DATABASE_LENGTH_NORMAL="${CONTAINER_DATABASE_LENGTH_NORMAL:-}"
CONTAINER_USER_NAME="${CONTAINER_USER_NAME:-}"
CONTAINER_USER_PASS="${CONTAINER_USER_PASS:-}"
CONTAINER_PASS_LENGTH="${CONTAINER_PASS_LENGTH:-}"
CONTAINER_ENV_USER_NAME="${CONTAINER_ENV_USER_NAME:-}"
CONTAINER_ENV_PASS_NAME="${CONTAINER_ENV_PASS_NAME:-}"
CONTAINER_SERVICES_LIST="${CONTAINER_SERVICES_LIST:-}"
CONTAINER_MOUNT_DATA_ENABLED="${CONTAINER_MOUNT_DATA_ENABLED:-}"
CONTAINER_MOUNT_DATA_MOUNT_DIR="${CONTAINER_MOUNT_DATA_MOUNT_DIR:-}"
CONTAINER_MOUNT_CONFIG_ENABLED="${CONTAINER_MOUNT_CONFIG_ENABLED:-}"
CONTAINER_MOUNT_CONFIG_MOUNT_DIR="${CONTAINER_MOUNT_CONFIG_MOUNT_DIR:-}"
CONTAINER_MOUNTS="${CONTAINER_MOUNTS:-}"
CONTAINER_DEVICES="${CONTAINER_DEVICES:-}"
CONTAINER_ENV="${CONTAINER_ENV:-}"
CONTAINER_SYSCTL="${CONTAINER_SYSCTL:-}"
CONTAINER_LABELS="${CONTAINER_LABELS:-}"
CONTAINER_COMMANDS="${CONTAINER_COMMANDS:-}"
CONTAINER_DEBUG_ENABLED="${CONTAINER_DEBUG_ENABLED:-}"
CONTAINER_DEBUG_OPTIONS="${CONTAINER_DEBUG_OPTIONS:-}"
CONTAINER_CREATE_DIRECTORY="${CONTAINER_CREATE_DIRECTORY:-}"
#
DOCKER_SYS_ADMIN="\${ENV_DOCKER_SYS_ADMIN:-$DOCKER_SYS_ADMIN}"
DOCKER_CAP_CHOWN="\${ENV_DOCKER_CAP_CHOWN:-$DOCKER_CAP_CHOWN}"
DOCKER_CAP_NET_RAW="\${ENV_DOCKER_CAP_NET_RAW:-$DOCKER_CAP_NET_RAW}"
DOCKER_CAP_SYS_NICE="\${ENV_DOCKER_DOCKER_CAP_SYS_NICE:-$DOCKER_CAP_SYS_NICE}"
DOCKER_CAP_NET_ADMIN="\${ENV_DOCKER_CAP_NET_ADMIN:-$DOCKER_CAP_NET_ADMIN}"
DOCKER_CAP_NET_BIND_SERVICE="\${ENV_DOCKER_CAP_NET_BIND_SERVICE:-$DOCKER_CAP_NET_BIND_SERVICE}"

EOF
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
__dockermgr_password_variables() {
  [ -d "$DOCKERMGR_CONFIG_DIR/secure" ] || mkdir -p "$DOCKERMGR_CONFIG_DIR/secure"
  cat <<EOF | tee | tr '|' '\n' | __remove_extra_spaces
# Enviroment variables for $APPNAME
ENV_CONTAINER_ENV_PASS_NAME="${ENV_CONTAINER_ENV_PASS_NAME:-$CONTAINER_ENV_PASS_NAME}"
ENV_CONTAINER_DATABASE_PASS_ROOT="${ENV_CONTAINER_DATABASE_PASS_ROOT:-$CONTAINER_DATABASE_PASS_ROOT}"
ENV_CONTAINER_DATABASE_PASS_NORMAL="${ENV_CONTAINER_DATABASE_PASS_NORMAL:-$CONTAINER_DATABASE_PASS_NORMAL}"

EOF
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Define extra functions
__rport() {
  local port=""
  port="$(__port)"
  while :; do
    { [ $port -lt 50000 ] && [ $port -gt 50999 ]; } && port="$(__port)"
    __port_in_use "$port" && break
  done
  echo "$port" | head -n1
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
__trim() {
  local var="$*"
  var="${var#"${var%%[![:space:]]*}"}" # remove leading whitespace characters
  var="${var%"${var##*[![:space:]]}"}" # remove trailing whitespace characters
  printf '%s' "$var" | grep -v '^$' | __remove_extra_spaces
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
__test_public_reachable() {
  local exitCode=0
  local port="${1:-$(__port)}"
  local nc="$(builtin type -P nc || builtin type -P netcat || false)"
  if [ -n "$nc" ]; then
    (timeout 20 $nc -l $port &) &>/dev/null
    curl -q -LSsf -4 "https://ifconfig.co/port/$port" | jq -rc '.reachable' | grep -q 'true' || exitCode=1
  else
    exitCode=1
  fi
  return $exitCode
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
__create_docker_script() {
  [ -n "$EXECUTE_DOCKER_CMD" ] || return
  local replace_with="$HUB_IMAGE_URL:$HUB_IMAGE_TAG $CONTAINER_COMMANDS"
  create_docker_script_message_pre="${create_docker_script_message_pre:-Failed to execute $EXECUTE_PRE_INSTALL}"
  create_docker_script_message_post="${create_docker_script_message_post:-Failed to create $CONTAINER_NAME}"
  cat <<EOF | grep -v '^$' | sed 's/ --/\n  --/g;s| -d| -d \\|g' | grep -v '^$' | sed '/  --/ s/$/ \\/' | grep '^' | tee "$DOCKERMGR_INSTALL_SCRIPT" >/dev/null
#!/usr/bin/env bash
# Install script for $CONTAINER_NAME
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
$EXECUTE_PRE_INSTALL
statusCode=\$?
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if [ \$statusCode -ne 0 ]; then
  echo "$create_docker_script_message_pre" >&2
  exit 1
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
$EXECUTE_DOCKER_CMD
  $HUB_IMAGE_URL:$HUB_IMAGE_TAG $CONTAINER_COMMANDS
statusCode=\$?
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if [ \$statusCode -ne 0 ]; then
  echo "$create_docker_script_message_post" >&2
  exit 1
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if ! docker ps -a 2>&1 | grep -q "$CONTAINER_NAME"; then
echo "$CONTAINER_NAME is not running" >&2
  exit 1
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
exit 0
# end script

EOF
  unset create_docker_script_message_pre create_docker_script_message_post
  [ -f "$DOCKERMGR_INSTALL_SCRIPT" ] || return 1
  sed -i 's| '$HUB_IMAGE_URL':'$HUB_IMAGE_TAG' .*\\| \\|g' "$DOCKERMGR_INSTALL_SCRIPT"
  chmod -Rf 755 "$DOCKERMGR_INSTALL_SCRIPT"
}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
__printf_color() { printf_color "$2\n" "$1"; }
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# import variables from a file
[ -f "$INSTDIR/env.sh" ] && . "$INSTDIR/env.sh"
[ -f "$APPDIR/env.sh" ] && . "$APPDIR/env.sh"
[ -f "$DOCKERMGR_CONFIG_DIR/.env.sh" ] && . "$DOCKERMGR_CONFIG_DIR/.env.sh"
[ -f "$DOCKERMGR_CONFIG_DIR/env/$APPNAME.conf" ] && . "$DOCKERMGR_CONFIG_DIR/env/$APPNAME.conf"
[ -f "$DOCKERMGR_CONFIG_DIR/env/$APPNAME.custom.conf" ] && . "$DOCKERMGR_CONFIG_DIR/env/$APPNAME.custom.conf"
[ -r "$DOCKERMGR_CONFIG_DIR/secure/$APPNAME" ] && . "$DOCKERMGR_CONFIG_DIR/secure/$APPNAME"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Initialize the installer
dockermgr_run_init
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Run pre-install commands
execute "__run_pre_install" "Running pre-installation commands"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
ensure_dirs
ensure_perms
mkdir -p "$DOCKERMGR_CONFIG_DIR/env"
mkdir -p "$DOCKERMGR_CONFIG_DIR/secure"
mkdir -p "$DOCKERMGR_CONFIG_DIR/scripts"
mkdir -p "$DOCKERMGR_CONFIG_DIR/installed"
mkdir -p "$DOCKERMGR_CONFIG_DIR/containers"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# fix directory permissions
chmod -f 777 "$APPDIR"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# variable cleanup
HUB_IMAGE_TAG="${HUB_IMAGE_TAG//*:/}"
HUB_IMAGE_URL="${HUB_IMAGE_URL//*:\/\//}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# verify required file exists
if [ -n "$CONTAINER_REQUIRES" ]; then
  CONTAINER_REQUIRES="${CONTAINER_REQUIRES//,/}"
  for required in $CONTAINER_REQUIRES; do
    if [ ! -e "$required" ] || [ -z "$(type "$required" 2>/dev/null)" ]; then
      required_missing="$required $required_missing"
    fi
  done
  [ "$required_missing" != " " ] || unset required_missing
  if [ -n "$required_missing" ]; then
    echo "Missing required: $required_missing"
    exit 1
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# rewrite variables from env file
SET_LAN_DEV="${ENV_SET_LAN_DEV:-$SET_LAN_DEV}"
SET_LAN_IP="${ENV_SET_LAN_IP:-$SET_LAN_IP}"
SET_LAN_IP="${ENV_SET_LAN_IP:-$SET_LAN_IP}"
SET_DOCKER_IP="${ENV_SET_DOCKER_IP:-$SET_DOCKER_IP}"
SET_LOCAL_HOSTNAME="${ENV_SET_LOCAL_HOSTNAME:-$SET_LOCAL_HOSTNAME}"
SET_LONG_HOSTNAME="${ENV_SET_LONG_HOSTNAME:-$SET_LONG_HOSTNAME}"
SET_SHORT_HOSTNAME="${ENV_SET_SHORT_HOSTNAME:-$SET_SHORT_HOSTNAME}"
SET_DOMAIN_NAME="${ENV_SET_DOMAIN_NAME:-$SET_DOMAIN_NAME}"
SET_HOST_FULL_NAME="${ENV_SET_HOST_FULL_NAME:-$SET_HOST_FULL_NAME}"
SET_HOST_FULL_DOMAIN="${ENV_SET_HOST_FULL_DOMAIN:-$SET_HOST_FULL_DOMAIN}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
HOST_DATA_DIR="${ENV_HOST_DATA_DIR:-$HOST_DATA_DIR}"
HOST_CONFIG_DIR="${ENV_HOST_CONFIG_DIR:-$HOST_CONFIG_DIR}"
HOST_SSL_DIR="${ENV_HOST_SSL_DIR:-$HOST_SSL_DIR}"
HOST_SSL_CA="${ENV_HOST_SSL_CA:-$HOST_SSL_CA}"
HOST_SSL_CRT="${ENV_HOST_SSL_CRT:-$HOST_SSL_CRT}"
HOST_SSL_KEY="${ENV_HOST_SSL_KEY:-$HOST_SSL_KEY}"
HOST_RESOLVE_ENABLED="${ENV_HOST_RESOLVE_ENABLED:-$HOST_RESOLVE_ENABLED}"
HOST_RESOLVE_FILE="${ENV_HOST_RESOLVE_FILE:-$HOST_RESOLVE_FILE}"
HOST_ETC_HOSTS_ENABLED="${ENV_HOST_ETC_HOSTS_ENABLED:-$HOST_ETC_HOSTS_ENABLED}"
HOST_ETC_HOSTS_MOUNT="${ENV_HOST_ETC_HOSTS_MOUNT:-$HOST_ETC_HOSTS_MOUNT}"
HOST_DOCKER_CONFIG="${ENV_HOST_DOCKER_CONFIG:-$HOST_DOCKER_CONFIG}"
HOST_SOUND_DEVICE="${ENV_HOST_SOUND_DEVICE:-$HOST_SOUND_DEVICE}"
HOST_X11_DISPLAY="${ENV_HOST_X11_DISPLAY:-$HOST_X11_DISPLAY}"
HOST_X11_SOCKET="${ENV_HOST_X11_SOCKET:-$HOST_X11_SOCKET}"
HOST_X11_XAUTH="${ENV_HOST_X11_XAUTH:-$HOST_X11_XAUTH}"
HOST_DOCKER_NETWORK="${ENV_HOST_DOCKER_NETWORK:-$HOST_DOCKER_NETWORK}"
HOST_DOCKER_LINK="${ENV_HOST_DOCKER_LINK:-$HOST_DOCKER_LINK}"
HOST_NETWORK_ADDR="${ENV_HOST_NETWORK_ADDR:-$HOST_NETWORK_ADDR}"
HOST_NGINX_ENABLED="${ENV_HOST_NGINX_ENABLED:-$HOST_NGINX_ENABLED}"
HOST_NGINX_SSL_ENABLED="${ENV_HOST_NGINX_SSL_ENABLED:-$HOST_NGINX_SSL_ENABLED}"
HOST_NGINX_HTTP_PORT="${ENV_HOST_NGINX_HTTP_PORT:-$HOST_NGINX_HTTP_PORT}"
HOST_NGINX_HTTPS_PORT="${ENV_HOST_NGINX_HTTPS_PORT:-$HOST_NGINX_HTTPS_PORT}"
HOST_NGINX_UPDATE_CONF="${ENV_HOST_NGINX_UPDATE_CONF:-$HOST_NGINX_UPDATE_CONF}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
CONTAINER_NAME="${ENV_CONTAINER_NAME:-${CONTAINER_NAME:-}}"
CONTAINER_SSL_DIR="${ENV_CONTAINER_SSL_DIR:-$CONTAINER_SSL_DIR}"
CONTAINER_SSL_CA="${ENV_CONTAINER_SSL_CA:-$CONTAINER_SSL_CA}"
CONTAINER_SSL_CRT="${ENV_CONTAINER_SSL_CRT:-$CONTAINER_SSL_CRT}"
CONTAINER_SSL_KEY="${ENV_CONTAINER_SSL_KEY:-$CONTAINER_SSL_KEY}"
CONTAINER_REQUIRES="${ENV_CONTAINER_REQUIRES:-$CONTAINER_REQUIRES}"
CONTAINER_TIMEZONE="${ENV_CONTAINER_TIMEZONE:-$CONTAINER_TIMEZONE}"
CONTAINER_WORK_DIR="${ENV_CONTAINER_WORK_DIR:-$CONTAINER_WORK_DIR}"
CONTAINER_HTML_DIR="${ENV_CONTAINER_HTML_DIR:-$CONTAINER_HTML_DIR}"
CONTAINER_HTML_ENV="${ENV_CONTAINER_HTML_ENV:-$CONTAINER_HTML_ENV}"
CONTAINER_USER_ID="${ENV_CONTAINER_USER_ID:-$CONTAINER_USER_ID}"
CONTAINER_GROUP_ID="${ENV_CONTAINER_GROUP_ID:-$CONTAINER_GROUP_ID}"
CONTAINER_USER_RUN="${ENV_CONTAINER_USER_RUN:-$CONTAINER_USER_RUN}"
CONTAINER_PRIVILEGED_ENABLED="${ENV_CONTAINER_PRIVILEGED_ENABLED:-$CONTAINER_PRIVILEGED_ENABLED}"
CONTAINER_SHM_SIZE="${ENV_CONTAINER_SHM_SIZE:-$CONTAINER_SHM_SIZE}"
CONTAINER_RAM_SIZE="${ENV_CONTAINER_RAM_SIZE:-$CONTAINER_RAM_SIZE}"
CONTAINER_SWAP_SIZE="${ENV_CONTAINER_SWAP_SIZE:-$CONTAINER_SWAP_SIZE}"
CONTAINER_CPU_COUNT="${ENV_CONTAINER_CPU_COUNT:-$CONTAINER_CPU_COUNT}"
CONTAINER_AUTO_RESTART="${ENV_CONTAINER_AUTO_RESTART:-$CONTAINER_AUTO_RESTART}"
CONTAINER_AUTO_DELETE="${ENV_CONTAINER_AUTO_DELETE:-$CONTAINER_AUTO_DELETE}"
CONTAINER_TTY_ENABLED="${ENV_CONTAINER_TTY_ENABLED:-$CONTAINER_TTY_ENABLED}"
CONTAINER_INTERACTIVE_ENABLED="${ENV_CONTAINER_INTERACTIVE_ENABLED:-$CONTAINER_INTERACTIVE_ENABLED}"
CONTAINER_ENV_FILE_ENABLED="${ENV_CONTAINER_ENV_FILE_ENABLED:-$CONTAINER_ENV_FILE_ENABLED}"
CONTAINER_ENV_FILE_MOUNT="${ENV_CONTAINER_ENV_FILE_MOUNT:-$CONTAINER_ENV_FILE_MOUNT}"
CONTAINER_DOCKER_CONFIG_FILE="${ENV_CONTAINER_DOCKER_CONFIG_FILE:-$CONTAINER_DOCKER_CONFIG_FILE}"
CONTAINER_SOUND_DEVICE_FILE="${ENV_CONTAINER_SOUND_DEVICE_FILE:-$CONTAINER_SOUND_DEVICE_FILE}"
CONTAINER_X11_ENABLED="${ENV_CONTAINER_X11_ENABLED:-$CONTAINER_X11_ENABLED}"
CONTAINER_X11_SOCKET="${ENV_CONTAINER_X11_SOCKET:-$CONTAINER_X11_SOCKET}"
CONTAINER_X11_XAUTH="${ENV_CONTAINER_X11_XAUTH:-$CONTAINER_X11_XAUTH}"
CONTAINER_HOSTNAME="${ENV_HOSTNAME:-${ENV_CONTAINER_HOSTNAME:-$CONTAINER_HOSTNAME}}"
CONTAINER_DOMAINNAME="${ENV_DOMAINNAME:-${ENV_CONTAINER_DOMAINNAME:-$CONTAINER_DOMAINNAME}}"
CONTAINER_WEB_SERVER_ENABLED="${ENV_CONTAINER_WEB_SERVER_ENABLED:-$CONTAINER_WEB_SERVER_ENABLED}"
CONTAINER_WEB_SERVER_INT_PORT="${ENV_CONTAINER_WEB_SERVER_INT_PORT:-$CONTAINER_WEB_SERVER_INT_PORT}"
CONTAINER_WEB_SERVER_SSL_ENABLED="${ENV_CONTAINER_WEB_SERVER_SSL_ENABLED:-$CONTAINER_WEB_SERVER_SSL_ENABLED}"
CONTAINER_WEB_SERVER_AUTH_ENABLED="${ENV_CONTAINER_WEB_SERVER_AUTH_ENABLED:-$CONTAINER_WEB_SERVER_AUTH_ENABLED}"
CONTAINER_WEB_SERVER_LISTEN_ON="${ENV_CONTAINER_WEB_SERVER_LISTEN_ON:-$CONTAINER_WEB_SERVER_LISTEN_ON}"
CONTAINER_WEB_SERVER_VHOSTS="${ENV_CONTAINER_WEB_SERVER_VHOSTS:-$CONTAINER_WEB_SERVER_VHOSTS}"
CONTAINER_WEB_SERVER_CONFIG_NAME="${ENV_CONTAINER_WEB_SERVER_CONFIG_NAME:-$CONTAINER_WEB_SERVER_CONFIG_NAME}"
CONTAINER_ADD_CUSTOM_PORT="${ENV_CONTAINER_ADD_CUSTOM_PORT:-$CONTAINER_ADD_CUSTOM_PORT}"
CONTAINER_PROTOCOL="${ENV_CONTAINER_PROTOCOL:-$CONTAINER_PROTOCOL}"
CONTAINER_DNS="${ENV_CONTAINER_DNS:-$CONTAINER_DNS}"
CONTAINER_DATABASE_LISTEN="${ENV_CONTAINER_DATABASE_LISTEN:-$CONTAINER_DATABASE_LISTEN}"
CONTAINER_REDIS_ENABLED="${ENV_CONTAINER_REDIS_ENABLED:-$CONTAINER_REDIS_ENABLED}"
CONTAINER_SQLITE3_ENABLED="${ENV_CONTAINER_SQLITE3_ENABLED:-$CONTAINER_SQLITE3_ENABLED}"
CONTAINER_MARIADB_ENABLED="${ENV_CONTAINER_MARIADB_ENABLED:-$CONTAINER_MARIADB_ENABLED}"
CONTAINER_MONGODB_ENABLED="${ENV_CONTAINER_MONGODB_ENABLED:-$CONTAINER_MONGODB_ENABLED}"
CONTAINER_COUCHDB_ENABLED="${ENV_CONTAINER_COUCHDB_ENABLED:-$CONTAINER_COUCHDB_ENABLED}"
CONTAINER_POSTGRES_ENABLED="${ENV_CONTAINER_POSTGRES_ENABLED:-$CONTAINER_POSTGRES_ENABLED}"
CONTAINER_SUPABASE_ENABLED="${ENV_CONTAINER_SUPABASE_ENABLED:-$CONTAINER_SUPABASE_ENABLED}"
CONTAINER_DATABASE_USER_ROOT="${ENV_CONTAINER_DATABASE_USER_ROOT:-$CONTAINER_DATABASE_USER_ROOT}"
CONTAINER_DATABASE_PASS_ROOT="${ENV_CONTAINER_DATABASE_PASS_ROOT:-$CONTAINER_DATABASE_PASS_ROOT}"
CONTAINER_DATABASE_LENGTH_ROOT="${ENV_CONTAINER_DATABASE_LENGTH_ROOT:-$CONTAINER_DATABASE_LENGTH_ROOT}"
CONTAINER_DATABASE_USER_NORMAL="${ENV_CONTAINER_DATABASE_USER_NORMAL:-$CONTAINER_DATABASE_USER_NORMAL}"
CONTAINER_DATABASE_PASS_NORMAL="${ENV_CONTAINER_DATABASE_PASS_NORMAL:-$CONTAINER_DATABASE_PASS_NORMAL}"
CONTAINER_DATABASE_LENGTH_NORMAL="${ENV_CONTAINER_DATABASE_LENGTH_NORMAL:-$CONTAINER_DATABASE_LENGTH_NORMAL}"
CONTAINER_USER_NAME="${ENV_CONTAINER_USER_NAME:-$CONTAINER_USER_NAME}"
CONTAINER_USER_PASS="${ENV_CONTAINER_USER_PASS:-$CONTAINER_USER_PASS}"
CONTAINER_PASS_LENGTH="${ENV_CONTAINER_PASS_LENGTH:-$CONTAINER_PASS_LENGTH}"
CONTAINER_ENV_USER_NAME="${ENV_CONTAINER_ENV_USER_NAME:-$CONTAINER_ENV_USER_NAME}"
CONTAINER_ENV_PASS_NAME="${ENV_CONTAINER_ENV_PASS_NAME:-$CONTAINER_ENV_PASS_NAME}"
CONTAINER_EMAIL_ENABLED="${ENV_CONTAINER_EMAIL_ENABLED:-$CONTAINER_EMAIL_ENABLED}"
CONTAINER_EMAIL_USER="${ENV_CONTAINER_EMAIL_USER:-$CONTAINER_EMAIL_USER}"
CONTAINER_EMAIL_DOMAIN="${ENV_CONTAINER_EMAIL_DOMAIN:-$CONTAINER_EMAIL_DOMAIN}"
CONTAINER_EMAIL_RELAY="${ENV_CONTAINER_EMAIL_RELAY:-$CONTAINER_EMAIL_RELAY}"
CONTAINER_SERVICES_LIST="${ENV_CONTAINER_SERVICES_LIST:-$CONTAINER_SERVICES_LIST}"
CONTAINER_MOUNT_DATA_ENABLED="${ENV_CONTAINER_MOUNT_DATA_ENABLED:-$CONTAINER_MOUNT_DATA_ENABLED}"
CONTAINER_MOUNT_DATA_MOUNT_DIR="${ENV_CONTAINER_MOUNT_DATA_MOUNT_DIR:-$CONTAINER_MOUNT_DATA_MOUNT_DIR}"
CONTAINER_MOUNT_CONFIG_ENABLED="${ENV_CONTAINER_MOUNT_CONFIG_ENABLED:-$CONTAINER_MOUNT_CONFIG_ENABLED}"
CONTAINER_MOUNT_CONFIG_MOUNT_DIR="${ENV_CONTAINER_MOUNT_CONFIG_MOUNT_DIR:-$CONTAINER_MOUNT_CONFIG_MOUNT_DIR}"
CONTAINER_MOUNTS="${ENV_CONTAINER_MOUNTS:-$CONTAINER_MOUNTS}"
CONTAINER_DEVICES="${ENV_CONTAINER_DEVICES:-$CONTAINER_DEVICES}"
CONTAINER_ENV="${ENV_CONTAINER_ENV:-$CONTAINER_ENV}"
CONTAINER_SYSCTL="${ENV_CONTAINER_SYSCTL:-$CONTAINER_SYSCTL}"
CONTAINER_LABELS="${ENV_CONTAINER_LABELS:-$CONTAINER_LABELS}"
CONTAINER_COMMANDS="${ENV_CONTAINER_COMMANDS:-$CONTAINER_COMMANDS}"
CONTAINER_DEBUG_ENABLED="${ENV_CONTAINER_DEBUG_ENABLED:-$CONTAINER_DEBUG_ENABLED}"
CONTAINER_DEBUG_OPTIONS="${ENV_CONTAINER_DEBUG_OPTIONS:-$CONTAINER_DEBUG_OPTIONS}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
DOCKER_SYS_ADMIN="${ENV_DOCKER_SYS_ADMIN:-$DOCKER_SYS_ADMIN}"
DOCKER_CAP_CHOWN="${ENV_DOCKER_CAP_CHOWN:-$DOCKER_CAP_CHOWN}"
DOCKER_CAP_NET_RAW="${ENV_DOCKER_CAP_NET_RAW:-$DOCKER_CAP_NET_RAW}"
DOCKER_CAP_SYS_NICE="${ENV_DOCKER_CAP_SYS_NICE:-$DOCKER_CAP_SYS_NICE}"
DOCKER_CAP_NET_ADMIN="${ENV_DOCKER_CAP_NET_ADMIN:-$DOCKER_CAP_NET_ADMIN}"
DOCKER_CAP_NET_BIND_SERVICE="${ENV_DOCKER_CAP_NET_BIND_SERVICE:-$DOCKER_CAP_NET_BIND_SERVICE}"
DOCKERMGR_ENABLE_INSTALL_SCRIPT="${SCRIPT_ENABLED:-$DOCKERMGR_ENABLE_INSTALL_SCRIPT}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# SSL Setup container mounts
CONTAINER_SSL_DIR="${CONTAINER_SSL_DIR:-/config/ssl}"
CONTAINER_SSL_CA="${CONTAINER_SSL_CA:-$CONTAINER_SSL_DIR/ca.crt}"
CONTAINER_SSL_CRT="${CONTAINER_SSL_CRT:-$CONTAINER_SSL_DIR/localhost.crt}"
CONTAINER_SSL_KEY="${CONTAINER_SSL_KEY:-$CONTAINER_SSL_DIR/localhost.key}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup ssl certs
if [ "$CONTAINER_WEB_SERVER_SSL_ENABLED" = "true" ]; then
  if [ -z "$HOST_SSL_CA" ]; then
    if [ -f "/etc/ssl/cert.pem" ]; then
      HOST_SSL_CA="/etc/ssl/cert.pem"
    elif [ -f "/etc/ssl/certs/ca-bundle.crt" ]; then
      HOST_SSL_CA="/etc/ssl/certs/ca-bundle.crt"
    elif [ -f "/etc/ssl/CA/CasjaysDev/certs/ca.crt" ]; then
      HOST_SSL_CA="/etc/ssl/CA/CasjaysDev/certs/ca.crt"
    fi
  fi
  if [ -z "$HOST_SSL_CRT" ]; then
    if [ -f "/etc/letsencrypt/live/domain/fullchain.pem" ]; then
      HOST_SSL_CRT="/etc/letsencrypt/live/domain/fullchain.pem"
    elif [ -f "/etc/ssl/CA/CasjaysDev/certs/localhost.crt" ]; then
      HOST_SSL_CRT="/etc/ssl/CA/CasjaysDev/certs/localhost.crt"
    fi
  fi
  if [ -z "$HOST_SSL_KEY" ]; then
    if [ -f "/etc/letsencrypt/live/domain/privkey.pem" ]; then
      HOST_SSL_KEY="/etc/letsencrypt/live/domain/privkey.pem"
    elif [ -f "/etc/ssl/CA/CasjaysDev/private/localhost.key" ]; then
      HOST_SSL_KEY="/etc/ssl/CA/CasjaysDev/private/localhost.key"
    fi
  fi
  if [ -n "$HOST_SSL_CA" ]; then
    HOST_SSL_CA="$(realpath "$HOST_SSL_CA")"
  fi
  if [ -n "$HOST_SSL_CRT" ]; then
    HOST_SSL_CRT="$(realpath "$HOST_SSL_CRT")"
  fi
  if [ -n "$HOST_SSL_KEY" ]; then
    HOST_SSL_KEY="$(realpath "$HOST_SSL_KEY")"
  fi
  SSL_ENABLED="yes"
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup arrays/empty variables
PRETTY_PORT=""
SET_WEB_PORT_TMP=()
SET_CAPABILITIES=()
DOCKER_SET_OPTIONS=()
CONTAINER_ENV_PORTS=()
DOCKER_SET_TMP_PUBLISH=()
NGINX_REPLACE_INCLUDE=""
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Ensure that the image has a tag
if [ -z "$HUB_IMAGE_TAG" ]; then
  HUB_IMAGE_TAG="latest"
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if [ -z "$HUB_IMAGE_URL" ] || [ "$HUB_IMAGE_URL" = " " ]; then
  printf_exit "Please set the url to the containers image"
elif echo "$HUB_IMAGE_URL" | grep -q ':'; then
  HUB_IMAGE_URL="$(echo "$HUB_IMAGE_URL" | awk -F':' '{print $1}')"
  HUB_IMAGE_TAG="${HUB_IMAGE_TAG:-$(echo "$HUB_IMAGE_URL" | awk -F':' '{print $2}')}"
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set containers name
if [ -z "$CONTAINER_NAME" ]; then
  CONTAINER_NAME="$(__container_name || echo "${HUB_IMAGE_URL//\/-/}-$HUB_IMAGE_TAG")"
fi
DOCKER_SET_OPTIONS+=("--name=$CONTAINER_NAME")
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup time zone
if [ -z "$CONTAINER_TIMEZONE" ]; then
  CONTAINER_TIMEZONE="America/New_York"
fi
DOCKER_SET_OPTIONS+=("--env TZ=$CONTAINER_TIMEZONE")
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# set working dir
if [ -n "$CONTAINER_WORK_DIR" ]; then
  DOCKER_SET_OPTIONS+=("--workdir $CONTAINER_WORK_DIR")
  DOCKER_SET_OPTIONS+=("--env WORKDIR=$CONTAINER_WORK_DIR")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the html directory
if [ -n "$CONTAINER_HTML_DIR" ]; then
  if [ -z "$CONTAINER_HTML_ENV" ]; then
    CONTAINER_HTML_ENV="WWW_ROOT_DIR"
  fi
  DOCKER_SET_OPTIONS+=("--env $CONTAINER_HTML_ENV=$CONTAINER_HTML_DIR")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set user ID
if [ "$USER_ID_ENABLED" = "yes" ]; then
  if [ -z "$CONTAINER_USER_ID" ]; then
    DOCKER_SET_OPTIONS+=("--env PUID=$(id -u)")
  else
    DOCKER_SET_OPTIONS+=("--env PUID=$CONTAINER_USER_ID")
  fi
  if [ -z "$CONTAINER_GROUP_ID" ]; then
    DOCKER_SET_OPTIONS+=("--env PGID=$(id -g)")
  else
    DOCKER_SET_OPTIONS+=("--env PGID=$CONTAINER_GROUP_ID")
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the process owner
if [ -n "$CONTAINER_USER_RUN" ]; then
  DOCKER_SET_OPTIONS+=("--env USER=$CONTAINER_USER_RUN")
  DOCKER_SET_OPTIONS+=("--env SERVICE_USER=$CONTAINER_USER_RUN")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Run the container privileged
if [ "$CONTAINER_PRIVILEGED_ENABLED" = "yes" ]; then
  DOCKER_SET_OPTIONS+=("--privileged")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set ram size
if [ -n "$CONTAINER_RAM_SIZE" ]; then
  CONTAINER_RAM_SIZE=$((1024 * 1024 * $CONTAINER_RAM_SIZE))
  DOCKER_SET_OPTIONS+=("--memory $CONTAINER_RAM_SIZE")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set swap size
if [ -n "$CONTAINER_SWAP_SIZE" ]; then
  CONTAINER_SWAP_SIZE=$((1024 * 1024 * $CONTAINER_SWAP_SIZE))
  DOCKER_SET_OPTIONS+=("--memory-swap $CONTAINER_SWAP_SIZE")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set CPU count
if [ -z "$CONTAINER_CPU_COUNT" ] && [ -f "/proc/cpuinfo" ]; then
  CONTAINER_CPU_COUNT="$(grep -c '^processor' /proc/cpuinfo || echo '1')"
fi
if [ -n "$CONTAINER_CPU_COUNT" ]; then
  DOCKER_SET_OPTIONS+=("--cpus $CONTAINER_CPU_COUNT")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the containers SHM size
if [ -z "$CONTAINER_SHM_SIZE" ]; then
  DOCKER_SET_OPTIONS+=("--shm-size=128M")
else
  DOCKER_SET_OPTIONS+=("--shm-size=$CONTAINER_SHM_SIZE")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Auto restart the container
if [ -z "$CONTAINER_AUTO_RESTART" ]; then
  DOCKER_SET_OPTIONS+=("--restart unless-stopped")
else
  DOCKER_SET_OPTIONS+=("--restart=$CONTAINER_AUTO_RESTART")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Only run the container to execute command and then delete
if [ "$CONTAINER_AUTO_DELETE" = "yes" ]; then
  DOCKER_SET_OPTIONS+=("--rm")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Enable the tty
if [ "$CONTAINER_TTY_ENABLED" = "yes" ]; then
  DOCKER_SET_OPTIONS+=("--tty")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Run in interactive mode
if [ "$CONTAINER_INTERACTIVE_ENABLED" = "yes" ]; then
  DOCKER_SET_OPTIONS+=("--interactive")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Mount cgroups in the container
if [ -e "$CGROUPS_MOUNTS" ] || [ -e "/sys/fs/cgroup" ]; then
  if [ "$CGROUPS_ENABLED" = "yes" ]; then
    if [ -z "$CGROUPS_MOUNTS" ]; then
      DOCKER_SET_OPTIONS+=("--volume /sys/fs/cgroup:/sys/fs/cgroup:ro")
    else
      DOCKER_SET_OPTIONS+=("--volume $CGROUPS_MOUNTS")
    fi
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Mount the docker socket
if [ -f "$DOCKER_SOCKET_MOUNT" ] || [ -f "/var/run/docker.sock" ]; then
  if [ "$DOCKER_SOCKET_ENABLED" = "yes" ]; then
    if [ -z "$DOCKER_SOCKET_MOUNT" ]; then
      DOCKER_SET_OPTIONS+=("--volume /var/run/docker.sock:/var/run/docker.sock")
    else
      DOCKER_SET_OPTIONS+=("--volume $DOCKER_SOCKET_MOUNT:/var/run/docker.sock")
    fi
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Mount docker config in the container
if [ -f "$CONTAINER_DOCKER_CONFIG_FILE" ] || [ -f "/root/.docker/config.json" ] || [ -f "$HOME/.docker/config.json" ]; then
  if [ "$DOCKER_CONFIG_ENABLED" = "yes" ]; then
    if [ -z "$CONTAINER_DOCKER_CONFIG_FILE" ]; then
      CONTAINER_DOCKER_CONFIG_FILE="/root/.docker/config.json"
    fi
    if [ -n "$HOST_DOCKER_CONFIG" ]; then
      DOCKER_SET_OPTIONS+=("--volume $HOST_DOCKER_CONFIG:$CONTAINER_DOCKER_CONFIG_FILE:ro")
    elif [ -f "$HOME/.docker/config.json" ]; then
      DOCKER_SET_OPTIONS+=("--volume $HOME/.docker/config.json:$CONTAINER_DOCKER_CONFIG_FILE:ro")
    fi
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Mount sound card in container
if [ -e "$HOST_SOUND_DEVICE_FILE" ] || [ -e "/dev/snd" ]; then
  if [ "$DOCKER_SOUND_ENABLED" = "yes" ]; then
    if [ -z "$HOST_SOUND_DEVICE_FILE" ]; then
      HOST_SOUND_DEVICE_FILE="/dev/snd"
    fi
    if [ -z "$CONTAINER_SOUND_DEVICE_FILE" ]; then
      CONTAINER_SOUND_DEVICE_FILE="/dev/snd"
    fi
    if [ -n "$HOST_SOUND_DEVICE_FILE" ] && [ -n "$CONTAINER_SOUND_DEVICE_FILE" ]; then
      DOCKER_SET_OPTIONS+=("--device $HOST_SOUND_DEVICE_FILE:$CONTAINER_SOUND_DEVICE_FILE")
    fi
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup display if enabled
if [ "$CONTAINER_X11_ENABLED" = "yes" ]; then
  if [ -z "$HOST_X11_DISPLAY" ] && [ -n "$DISPLAY" ]; then
    HOST_X11_DISPLAY="${DISPLAY//*:/}"
  fi
  if [ -z "$HOST_X11_SOCKET" ]; then
    HOST_X11_SOCKET="/tmp/.X11-unix"
  fi
  if [ -z "$HOST_X11_XAUTH" ]; then
    HOST_X11_XAUTH="$HOME/.Xauthority"
  fi
  if [ -n "$HOST_X11_DISPLAY" ] && [ -n "$HOST_X11_SOCKET" ] && [ -n "$HOST_X11_XAUTH" ]; then
    DOCKER_SET_OPTIONS+=("--env DISPLAY=:$HOST_X11_DISPLAY")
    DOCKER_SET_OPTIONS+=("--volume $HOST_X11_SOCKET:${CONTAINER_X11_SOCKET:-/tmp/.X11-unix}")
    DOCKER_SET_OPTIONS+=("--volume $HOST_X11_XAUTH:${CONTAINER_X11_XAUTH:-/home/x11user/.Xauthority}")
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup containers hostname
if __is_server && [ -z "$CONTAINER_HOSTNAME" ]; then
  CONTAINER_DOMAINNAME="$SET_HOST_FULL_DOMAIN"
  CONTAINER_HOSTNAME="$APPNAME.$SET_HOST_FULL_DOMAIN"
else
  CONTAINER_DOMAINNAME="${CONTAINER_DOMAINNAME:-$SET_HOST_FULL_DOMAIN}"
  CONTAINER_HOSTNAME="${CONTAINER_HOSTNAME:-$APPNAME.$SET_HOST_FULL_NAME}"
fi
if [ -n "$CONTAINER_HOSTNAME" ]; then
  DOCKER_SET_OPTIONS+=("--hostname $CONTAINER_HOSTNAME")
  DOCKER_SET_OPTIONS+=("--env HOSTNAME=$CONTAINER_HOSTNAME")
else
  DOCKER_SET_OPTIONS+=("--hostname $CONTAINER_NAME")
  DOCKER_SET_OPTIONS+=("--env HOSTNAME=$CONTAINER_NAME")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the domain name
if [ -n "$CONTAINER_DOMAINNAME" ]; then
  DOCKER_SET_OPTIONS+=("--domainname $CONTAINER_DOMAINNAME")
  DOCKER_SET_OPTIONS+=("--env DOMAINNAME=$CONTAINER_DOMAINNAME")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set the docker network
if [ "$HOST_DOCKER_NETWORK" = "host" ]; then
  DOCKER_SET_OPTIONS+=("--net-host")
else
  if [ -z "$HOST_DOCKER_NETWORK" ]; then
    HOST_DOCKER_NETWORK="bridge"
  fi
  DOCKER_SET_OPTIONS+=("--network $HOST_DOCKER_NETWORK")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Create network if needed
DOCKER_CREATE_NET="$(__docker_net_create)"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Container listen address [address:extPort:intPort]
HOST_LISTEN_ADDR="${HOST_LISTEN_ADDR:-$SET_LAN_IP}"
if [ "$HOST_NETWORK_ADDR" = "yes" ] || [ "$HOST_NETWORK_ADDR" = "lan" ]; then
  HOST_DEFINE_LISTEN="$SET_LAN_IP"
  HOST_LISTEN_ADDR="$SET_LAN_IP"
elif [ "$HOST_NETWORK_ADDR" = "public" ]; then
  if connect_test && __test_public_reachable; then
    HOST_DEFINE_LISTEN="0.0.0.0"
    HOST_LISTEN_ADDR=$(__public_ip)
  else
    HOST_DEFINE_LISTEN="$SET_LAN_IP"
    HOST_LISTEN_ADDR="$SET_LAN_IP"
  fi
elif [ "$HOST_NETWORK_ADDR" = "docker" ]; then
  HOST_DEFINE_LISTEN="$SET_DOCKER_IP"
  HOST_LISTEN_ADDR="$SET_DOCKER_IP"
elif [ "$HOST_NETWORK_ADDR" = "local" ]; then
  HOST_DEFINE_LISTEN="127.0.0.1"
  HOST_LISTEN_ADDR="127.0.0.1"
  CONTAINER_PRIVATE="yes"
else
  HOST_DEFINE_LISTEN="0.0.0.0"
  HOST_LISTEN_ADDR="$SET_LAN_IP"
fi
HOST_DEFINE_LISTEN="${HOST_DEFINE_LISTEN:-0.0.0.0}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup the listen address
if [ -n "$HOST_DEFINE_LISTEN" ]; then
  HOST_LISTEN_ADDR="${HOST_DEFINE_LISTEN//:*/}"
fi
HOST_LISTEN_ADDR="${HOST_LISTEN_ADDR:-$HOST_DEFINE_LISTEN}"
HOST_LISTEN_ADDR="${HOST_LISTEN_ADDR//0.0.0.0/$SET_LAN_IP}"
HOST_LISTEN_ADDR="${HOST_LISTEN_ADDR//:*/}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# # nginx
NGINX_DIR="/etc/nginx"
NGINX_VHOSTS_CONF_FILE_TMP="/tmp/$$.$APPNAME.conf"
NGINX_VHOSTS_INC_FILE_TMP="/tmp/$$.$APPNAME.inc.conf"
NGINX_VHOSTS_PROXY_FILE_TMP="/tmp/$$.$APPNAME.custom.conf"
if [ "$HOST_NGINX_ENABLED" = "yes" ]; then
  NINGX_WRITABLE="$(sudo -n true && sudo bash -c '[ -w "/etc/nginx" ] && echo "true" || false' || echo 'false')"
  if [ -n "$HOST_NGINX_HTTPS_PORT" ]; then
    NGINX_LISTEN_OPTS="ssl http2"
    NGINX_PORT="${HOST_NGINX_HTTPS_PORT:-443}"
  else
    NGINX_PORT="${HOST_NGINX_HTTP_PORT:-80}"
  fi
  if [ -f "/etc/nginx/nginx.conf" ] && [ "$NINGX_WRITABLE" = "true" ]; then
    NGINX_DIR="/etc/nginx"
  else
    NGINX_DIR="$HOME/.config/nginx"
  fi
  if [ "$CONTAINER_WEB_SERVER_AUTH_ENABLED" = "yes" ]; then
    NGINX_AUTH_DIR="$NGINX_DIR/auth"
    CONTAINER_USER_NAME="${CONTAINER_USER_NAME:-root}"
    CONTAINER_USER_PASS="${CONTAINER_USER_PASS:-$RANDOM_PASS}"
    if [ ! -d "$NGINX_AUTH_DIR" ]; then
      mkdir -p "$NGINX_AUTH_DIR"
    fi
    if [ -n "$(builtin type -P htpasswd)" ]; then
      if ! grep -q "$CONTAINER_USER_NAME"; then
        printf_yellow "Creating auth $NGINX_AUTH_DIR/$APPNAME"
        if [ -f "$NGINX_AUTH_DIR/$APPNAME" ]; then
          htpasswd -b "$NGINX_AUTH_DIR/$APPNAME" "$CONTAINER_USER_NAME" "$CONTAINER_USER_PASS" &>/dev/null
        else
          htpasswd -b -c "$NGINX_AUTH_DIR/$APPNAME" "$CONTAINER_USER_NAME" "$CONTAINER_USER_PASS" &>/dev/null
        fi
      fi
    fi
  fi
  if [ "$HOST_NGINX_UPDATE_CONF" = "yes" ]; then
    mkdir -p "$NGINX_DIR/vhosts.d"
  fi
  if [ ! -f "$NGINX_MAIN_CONFIG" ]; then
    HOST_NGINX_UPDATE_CONF="yes"
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup containers web server
if [ "$CONTAINER_WEB_SERVER_ENABLED" = "yes" ]; then
  if [ "$CONTAINER_WEB_SERVER_SSL_ENABLED" = "yes" ] || [ "$SSL_ENABLED" = "yes" ]; then
    DOCKER_SET_OPTIONS+=("--env SSL_ENABLED=true")
  fi
  if [ -n "$CONTAINER_WEB_SERVER_INT_PORT" ]; then
    CONTAINER_WEB_SERVER_INT_PORT="${CONTAINER_WEB_SERVER_INT_PORT//,/ }"
    DOCKER_SET_OPTIONS+=("--env WEB_PORT=\"$CONTAINER_WEB_SERVER_INT_PORT\"")
  fi
  if [ "$CONTAINER_WEB_SERVER_SSL_ENABLED" = "yes" ]; then
    CONTAINER_PROTOCOL="https"
  else
    CONTAINER_PROTOCOL="http"
  fi
  if [ -z "$CONTAINER_WEB_SERVER_LISTEN_ON" ]; then
    CONTAINER_WEB_SERVER_LISTEN_ON="$HOST_LISTEN_ADDR"
  fi
  NGINX_PROXY_ADDRESS="${CONTAINER_WEB_SERVER_LISTEN_ON:-$HOST_LISTEN_ADDR}"
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
if [ "$CONTAINER_HTTPS_PORT" != "" ]; then
  CONTAINER_PROTOCOL="https"
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup easy port settings
if [ "$CONTAINER_SERVICE_PUBLIC" = "yes" ] || [ "$CONTAINER_SERVICE_PUBLIC" = "0.0.0.0" ]; then
  CONTAINER_SERVICE_PUBLIC="0.0.0.0"
elif echo "$CONTAINER_SERVICE_PUBLIC" | grep -q '[0-9].*\.[0-9].*\.[0-9].*\.[0-9]'; then
  true
else
  CONTAINER_SERVICE_PUBLIC="127.0.0.1"
fi
if [ "$CONTAINER_IS_DNS_SERVER" = "yes" ]; then
  service_port="$(__netstat "53" | grep -v 'docker' && __port || echo "53")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:53/udp")
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:53/tcp")
  unset service_port
fi
if [ "$CONTAINER_IS_DHCP_SERVER" = "yes" ]; then
  service_port="$(__netstat "67" | grep -v 'docker' && __port || echo "67")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:67/udp")
  service_port="$(__netstat "68" | grep -v 'docker' && __port || echo "68")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:68/udp")
  unset service_port
fi
if [ "$CONTAINER_IS_TFTP_SERVER" = "yes" ]; then
  service_port="$(__netstat "69" | grep -v 'docker' && __port || echo "69")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:69/udp")
  unset service_port
fi
if [ "$CONTAINER_IS_SMTP_SERVER" = "yes" ]; then
  service_port="$(__netstat "25" | grep -v 'docker' && __port || echo "25")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:25/tcp")
  service_port="$(__netstat "465" | grep -v 'docker' && __port || echo "465")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:465/tcp")
  service_port="$(__netstat "587" | grep -v 'docker' && __port || echo "587")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:587/tcp")
  unset service_port
fi
if [ "$CONTAINER_IS_POP3_SERVER" = "yes" ]; then
  service_port="$(__netstat "110" | grep -v 'docker' && __port || echo "110")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:110/tcp")
  service_port="$(__netstat "995" | grep -v 'docker' && __port || echo "995")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:995/tcp")
  unset service_port
fi
if [ "$CONTAINER_IS_IMAP_SERVER" = "yes" ]; then
  service_port="$(__netstat "143" | grep -v 'docker' && __port || echo "143")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:143/tcp")
  service_port="$(__netstat "993" | grep -v 'docker' && __port || echo "993")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:993/tcp")
  unset service_port
fi
if [ "$CONTAINER_IS_TIME_SERVER" = "yes" ]; then
  service_port="$(__netstat "123" | grep -v 'docker' && __port || echo "123")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:123/udp")
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:123/tcp")
  unset service_port
fi
if [ "$CONTAINER_IS_TIME_SERVER" = "yes" ]; then
  service_port="$(__netstat "119" | grep -v 'docker' && __port || echo "119")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:119/tcp")
  service_port="$(__netstat "433" | grep -v 'docker' && __port || echo "433")"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_SERVICE_PUBLIC:$service_port:433/tcp")
  unset service_port
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Database setup
if [ -z "$CONTAINER_DATABASE_LISTEN" ]; then
  CONTAINER_DATABASE_LISTEN="0.0.0.0"
fi
if [ -z "$DATABASE_BASE_DIR" ]; then
  DATABASE_BASE_DIR="/data/db"
  DOCKER_SET_OPTIONS+=("--env DATABASE_BASE_DIR=$DATABASE_BASE_DIR")
fi
if [ "$CONTAINER_CUSTOM_DATABASE_ENABLED" = "yes" ] && [ -n "$CONTAINER_CUSTOM_DATABASE_NAME" ]; then
  SHOW_DATABASE_INFO="true"
  CONTAINER_DATABASE_ENABLED="yes"
  DATABASE_DIR_CUSTOM="${CONTAINER_CUSTOM_DATABASE_DIR:-$DATABASE_BASE_DIR/$CONTAINER_CUSTOM_DATABASE_NAME}"
  DOCKER_SET_OPTIONS+=("--volume $LOCAL_DATA_DIR/db/$DATABASE_DIR_CUSTOM:$DATABASE_DIR_CUSTOM:z")
  DOCKER_SET_OPTIONS+=("--env DATABASE_DIR_CUSTOM=$DATABASE_DIR_CUSTOM")
  CONTAINER_CUSTOM_DATABASE_PROTOCOL="${CONTAINER_CUSTOM_DATABASE_PROTOCOL:-file}"
  if echo "$CONTAINER_CUSTOM_DATABASE_PORT" | grep -q "^[0-9][0-9]"; then
    DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_DATABASE_LISTEN:$CONTAINER_CUSTOM_DATABASE_PORT:$CONTAINER_CUSTOM_DATABASE_PORT")
    CONTAINER_DATABASE_PROTO="$CONTAINER_CUSTOM_DATABASE_PROTOCOL://$HOST_LISTEN_ADDR:$CONTAINER_CUSTOM_DATABASE_PORT"
  else
    CONTAINER_DATABASE_PROTO="file:///$DATABASE_DIR_CUSTOM/"
  fi
  MESSAGE_CONTAINER_DATABASE="Database files are saved to:            $DATABASE_DIR_CUSTOM"
fi
if [ "$CONTAINER_REDIS_ENABLED" = "yes" ]; then
  SHOW_DATABASE_INFO="true"
  CONTAINER_DATABASE_ENABLED="yes"
  CONTAINER_DATABASE_PROTO="redis://$HOST_LISTEN_ADDR:6379"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_DATABASE_LISTEN:6379:6379")
  DATABASE_DIR_REDIS="${DATABASE_DIR_REDIS:-$DATABASE_BASE_DIR/redis}"
  DOCKER_SET_OPTIONS+=("--volume $LOCAL_DATA_DIR/db/redis:$DATABASE_DIR_REDIS:z")
  DOCKER_SET_OPTIONS+=("--env DATABASE_DIR_REDIS=$DATABASE_DIR_REDIS")
  MESSAGE_REDIS="Database files are saved to:            $DATABASE_DIR_REDIS"
fi
if [ "$CONTAINER_SQLITE3_ENABLED" = "yes" ]; then
  SHOW_DATABASE_INFO="true"
  CONTAINER_DATABASE_ENABLED="yes"
  DATABASE_DIR_SQLITE3="${DATABASE_DIR_SQLITE3:-$DATABASE_BASE_DIR/sqlite3}"
  DOCKER_SET_OPTIONS+=("--volume $LOCAL_DATA_DIR/db/sqlite3:$DATABASE_DIR_SQLITE3:z")
  DOCKER_SET_OPTIONS+=("--env DATABASE_DIR_SQLITE3=$DATABASE_DIR_SQLITE3")
  CONTAINER_DATABASE_PROTO="sqlite3://$DATABASE_DIR_SQLITE3"
  CONTAINER_CREATE_DIRECTORY+=" $DATABASE_DIR_SQLITE3"
  MESSAGE_SQLITE3="Database files are saved to:            $DATABASE_DIR_SQLITE3"
fi
if [ "$CONTAINER_POSTGRES_ENABLED" = "yes" ]; then
  SHOW_DATABASE_INFO="true"
  CONTAINER_DATABASE_ENABLED="yes"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_DATABASE_LISTEN:5432:5432")
  DATABASE_DIR_POSTGRES="${DATABASE_DIR_POSTGRES:-$DATABASE_BASE_DIR/pgsql}"
  DOCKER_SET_OPTIONS+=("--volume $LOCAL_DATA_DIR/db/postgres:$DATABASE_DIR_POSTGRES:z")
  DOCKER_SET_OPTIONS+=("--env DATABASE_DIR_POSTGRES=$DATABASE_DIR_POSTGRES")
  CONTAINER_DATABASE_PROTO="postgresql://$HOST_LISTEN_ADDR:5432"
  MESSAGE_PGSQL="Database files are saved to:            $DATABASE_DIR_POSTGRES"
fi
if [ "$CONTAINER_MARIADB_ENABLED" = "yes" ]; then
  SHOW_DATABASE_INFO="true"
  CONTAINER_DATABASE_ENABLED="yes"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_DATABASE_LISTEN:3306:3306")
  DATABASE_DIR_MARIADB="${DATABASE_DIR_MARIADB:-$DATABASE_BASE_DIR/mariadb}"
  DOCKER_SET_OPTIONS+=("--volume $LOCAL_DATA_DIR/db/mariadb:$DATABASE_DIR_MARIADB:z")
  DOCKER_SET_OPTIONS+=("--env DATABASE_DIR_MARIADB=$DATABASE_DIR_MARIADB")
  CONTAINER_DATABASE_PROTO="mysql://$HOST_LISTEN_ADDR:3306"
  MESSAGE_MARIADB="Database files are saved to:            $DATABASE_DIR_MARIADB"
fi
if [ "$CONTAINER_COUCHDB_ENABLED" = "yes" ]; then
  SHOW_DATABASE_INFO="true"
  CONTAINER_DATABASE_ENABLED="yes"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_DATABASE_LISTEN:5984:5984")
  DATABASE_DIR_COUCHDB="${DATABASE_DIR_COUCHDB:-$DATABASE_BASE_DIR/couchdb}"
  DOCKER_SET_OPTIONS+=("--volume $LOCAL_DATA_DIR/db/couchdb:$DATABASE_DIR_COUCHDB:z")
  DOCKER_SET_OPTIONS+=("--env DATABASE_DIR_COUCHDB=$DATABASE_DIR_COUCHDB")
  CONTAINER_DATABASE_PROTO="http://$HOST_LISTEN_ADDR:5984"
  MESSAGE_COUCHDB="Database files are saved to:            $DATABASE_DIR_COUCHDB"
fi
if [ "$CONTAINER_MONGODB_ENABLED" = "yes" ]; then
  SHOW_DATABASE_INFO="true"
  CONTAINER_DATABASE_ENABLED="yes"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_DATABASE_LISTEN:27017:27017")
  DATABASE_DIR_MONGODB="${DATABASE_DIR_MONGODB:-$DATABASE_BASE_DIR/mongodb}"
  DOCKER_SET_OPTIONS+=("--volume $LOCAL_DATA_DIR/db/mongodb:$DATABASE_DIR_MONGODB:z")
  DOCKER_SET_OPTIONS+=("--env DATABASE_DIR_MONGODB=$DATABASE_DIR_MONGODB")
  CONTAINER_DATABASE_PROTO="mongodb://$HOST_LISTEN_ADDR:27017"
  MESSAGE_MONGODB="Database files are saved to:            $DATABASE_DIR_MONGODB"
fi
if [ "$CONTAINER_SUPABASE_ENABLED" = "yes" ]; then
  SHOW_DATABASE_INFO="true"
  CONTAINER_DATABASE_ENABLED="yes"
  CONTAINER_DATABASE_PROTO="http://$HOST_LISTEN_ADDR:8000"
  DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_DATABASE_LISTEN:5432:5432")
  DATABASE_DIR_SUPABASE="${DATABASE_DIR_SUPABASE:-$DATABASE_BASE_DIR/supabase}"
  DOCKER_SET_OPTIONS+=("--volume $LOCAL_DATA_DIR/db/supabase:$DATABASE_DIR_SUPABASE:z")
  DOCKER_SET_OPTIONS+=("--env DATABASE_DIR_SUPABASE=$DATABASE_DIR_SUPABASE")
  MESSAGE_SUPABASE="Database files are saved to:            $DATABASE_DIR_SUPABASE"
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
if [ "$CONTAINER_DATABASE_ENABLED" = "yes" ]; then
  if [ -n "$CONTAINER_DATABASE_USER_ROOT" ]; then
    DOCKER_SET_OPTIONS+=("--env DATABASE_USER_ROOT=${CONTAINER_DATABASE_USER_ROOT:-root}")
  fi
  if [ -n "$CONTAINER_DATABASE_PASS_ROOT" ]; then
    if [ "$CONTAINER_DATABASE_PASS_ROOT" = "random" ]; then
      CONTAINER_DATABASE_PASS_ROOT="$(__password "${CONTAINER_DATABASE_LENGTH_ROOT:-12}")"
    fi
    DOCKER_SET_OPTIONS+=("--env DATABASE_PASS_ROOT=$CONTAINER_DATABASE_PASS_ROOT")
  fi
  if [ -n "$CONTAINER_DATABASE_USER_NORMAL" ]; then
    DOCKER_SET_OPTIONS+=("--env DATABASE_USER_NORMAL=${CONTAINER_DATABASE_USER_NORMAL:-$USER}")
  fi
  if [ -n "$CONTAINER_DATABASE_PASS_NORMAL" ]; then
    if [ "$CONTAINER_DATABASE_PASS_NORMAL" = "random" ]; then
      CONTAINER_DATABASE_PASS_NORMAL="$(__password "${CONTAINER_DATABASE_LENGTH_NORMAL:-12}")"
    fi
    DOCKER_SET_OPTIONS+=("--env DATABASE_PASS_NORMAL=$CONTAINER_DATABASE_PASS_NORMAL")
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# containers username and password configuration
if [ -n "$WEBVIRTMGR_USERNAME" ]; then
  CONTAINER_USER_NAME="$WEBVIRTMGR_USERNAME"
fi
if [ -n "$CONTAINER_USER_NAME" ]; then
  CONTAINER_USER_NAME="${WEBVIRTMGR_USERNAME:-${CONTAINER_USER_NAME:-$DEFAULT_USERNAME}}"
fi
if [ -n "$CONTAINER_USER_NAME" ]; then
  if [ -n "$CONTAINER_ENV_USER_NAME" ]; then
    DOCKER_SET_OPTIONS+=("--env ${CONTAINER_ENV_USER_NAME:-username}=\"$CONTAINER_USER_NAME\"")
  fi
fi
if [ -n "$WEBVIRTMGR_PASSWORD" ]; then
  CONTAINER_USER_PASS="$WEBVIRTMGR_PASSWORD"
fi
if [ -n "$CONTAINER_USER_PASS" ]; then
  if [ "$CONTAINER_USER_PASS" = "random" ]; then
    CONTAINER_USER_PASS="$(__password "${CONTAINER_PASS_LENGTH:-16}")"
  fi
  CONTAINER_USER_PASS="${WEBVIRTMGR_PASSWORD:-${CONTAINER_USER_PASS:-$DEFAULT_PASSWORD}}"
fi
if [ -n "$CONTAINER_USER_PASS" ]; then
  if [ -n "$CONTAINER_ENV_PASS_NAME" ]; then
    DOCKER_SET_OPTIONS+=("--env ${CONTAINER_ENV_PASS_NAME:-PASSWORD}=\"$CONTAINER_USER_PASS\"")
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup email variables
if [ "$CONTAINER_EMAIL_ENABLED" = "yes" ]; then
  if [ -n "$CONTAINER_EMAIL_DOMAIN" ]; then
    DOCKER_SET_OPTIONS+=("--env EMAIL_DOMAIN=$CONTAINER_EMAIL_DOMAIN")
  fi
  if [ -n "$CONTAINER_EMAIL_RELAY" ]; then
    DOCKER_SET_OPTIONS+=("--env EMAIL_RELAY=$CONTAINER_EMAIL_RELAY")
  fi
  if [ -n "$CONTAINER_EMAIL_USER" ]; then
    DOCKER_SET_OPTIONS+=("--env EMAIL_ADMIN=$CONTAINER_EMAIL_USER@")
  fi
  if [ -z "$CONTAINER_EMAIL_PORTS" ]; then
    CONTAINER_EMAIL_PORTS="25,465,587"
  fi
  CONTAINER_EMAIL_PORTS="$(echo "${CONTAINER_EMAIL_PORTS//,/ }" | tr ' ' '\n')"
  DOCKER_SET_OPTIONS+=("--env EMAIL_ENABLED=$CONTAINER_EMAIL_ENABLED")
  for port in $CONTAINER_EMAIL_PORTS; do
    DOCKER_SET_TMP_PUBLISH+=("--publish $HOST_LISTEN_ADDR:$port:$port")
  done
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# process list
if [ -n "$CONTAINER_SERVICES_LIST" ]; then
  DOCKER_SET_OPTIONS+=("--env PROCS_LIST=${CONTAINER_SERVICES_LIST// /,}")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup data mount point
if [ "$CONTAINER_MOUNT_DATA_ENABLED" = "yes" ]; then
  if [ -z "$CONTAINER_MOUNT_DATA_MOUNT_DIR" ]; then
    CONTAINER_MOUNT_DATA_MOUNT_DIR="/data"
  fi
  CONTAINER_MOUNT_DATA_MOUNT_DIR="${CONTAINER_MOUNT_DATA_MOUNT_DIR//:*/}"
  DOCKER_SET_OPTIONS+=("--volume $LOCAL_DATA_DIR:$CONTAINER_MOUNT_DATA_MOUNT_DIR:z")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set config mount point
if [ "$CONTAINER_MOUNT_CONFIG_ENABLED" = "yes" ]; then
  if [ -z "$CONTAINER_MOUNT_CONFIG_MOUNT_DIR" ]; then
    CONTAINER_MOUNT_CONFIG_MOUNT_DIR="/config"
  fi
  CONTAINER_MOUNT_CONFIG_MOUNT_DIR="${CONTAINER_MOUNT_CONFIG_MOUNT_DIR//:*/}"
  DOCKER_SET_OPTIONS+=("--volume $LOCAL_CONFIG_DIR:$CONTAINER_MOUNT_CONFIG_MOUNT_DIR:z")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# additional docker arguments
if [ -n "$DOCKER_CUSTOM_ARGUMENTS" ]; then
  DOCKER_CUSTOM_ARGUMENTS="${DOCKER_CUSTOM_ARGUMENTS//,/ }"
  DOCKER_SET_OPTIONS+=("$DOCKER_CUSTOM_ARGUMENTS")
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# debugging
if [ "$CONTAINER_DEBUG_ENABLED" = "yes" ]; then
  DOCKER_SET_OPTIONS+=("--env DEBUGGER=on")
  if [ -n "$CONTAINER_DEBUG_OPTIONS" ]; then
    DOCKER_SET_OPTIONS+=("--env DEBUGGER_OPTIONS=$CONTAINER_DEBUG_OPTIONS")
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Send command to container
if [ -n "$CONTAINER_COMMANDS" ]; then
  CONTAINER_COMMANDS="${CONTAINER_COMMANDS//,/ } "
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup links
if [ -n "$HOST_DOCKER_LINK" ]; then
  for link in $HOST_DOCKER_LINK; do
    [ -n "$link" ] && DOCKER_SET_LINK="--link $link "
  done
  unset link
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup dns
if [ -n "$CONTAINER_DNS" ]; then
  DOCKER_SET_DNS=""
  DOCKER_SET_OPTIONS+=("--env CUSTOM_DNS=true")
  CONTAINER_DNS="${CONTAINER_DNS//,/ }"
  for dns in $CONTAINER_DNS; do
    if [ "$dns" != "" ] && [ "$dns" != " " ]; then
      DOCKER_SET_DNS+="--dns $dns "
    fi
  done
  unset dns
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup mounts
if [ -n "$CONTAINER_MOUNTS" ]; then
  DOCKER_SET_MNT=""
  CONTAINER_MOUNTS="${CONTAINER_MOUNTS//,/ }"
  for mnt in $CONTAINER_MOUNTS; do
    if [ "$mnt" != "" ] && [ "$mnt" != " " ]; then
      echo "$mnt" | grep -q ':' || mnt="$mnt:$mnt"
      DOCKER_SET_MNT+="--volume $mnt "
    fi
  done
  unset mnt
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if [ -n "$CONTAINER_OPT_MOUNT_VAR" ]; then
  DOCKER_SET_MNT=""
  CONTAINER_OPT_MOUNT_VAR="${CONTAINER_OPT_MOUNT_VAR//,/ }"
  for mnt in $CONTAINER_OPT_MOUNT_VAR; do
    if [ "$mnt" != "" ] && [ "$mnt" != " " ]; then
      echo "$mnt" | grep -q ':' || mnt="$mnt:$mnt"
      DOCKER_SET_MNT+="--volume $mnt "
    fi
  done
  unset mnt
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup devices
if [ -n "$CONTAINER_DEVICES" ]; then
  DOCKER_SET_DEV=""
  CONTAINER_DEVICES="${CONTAINER_DEVICES//,/ }"
  for dev in $CONTAINER_DEVICES; do
    if [ "$dev" != "" ] && [ "$dev" != " " ]; then
      echo "$dev" | grep -q ':' || dev="$dev:$dev"
      DOCKER_SET_DEV+="--device $dev "
    fi
  done
  unset dev
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup enviroment variables
if [ -n "$CONTAINER_ENV" ]; then
  DOCKER_SET_ENV=""
  CONTAINER_ENV="${CONTAINER_ENV//,/ }"
  for env in $CONTAINER_ENV; do
    if [ "$env" != "" ] && [ "$env" != " " ]; then
      DOCKER_SET_ENV+="--env $env "
    fi
  done
  unset env
fi
if [ -n "$CONTAINER_OPT_ENV_VAR" ]; then
  CONTAINER_OPT_ENV_VAR="${CONTAINER_OPT_ENV_VAR//,/ }"
  for env in $CONTAINER_OPT_ENV_VAR; do
    if [ "$env" != "" ] && [ "$env" != " " ]; then
      DOCKER_SET_ENV+="--env $env "
    fi
  done
  unset env
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# setup capabilites
[ "$DOCKER_SYS_TIME" = "yes" ] && SET_CAPABILITIES+=("SYS_TIME")
[ "$DOCKER_SYS_ADMIN" = "yes" ] && SET_CAPABILITIES+=("SYS_ADMIN")
[ "$DOCKER_CAP_CHOWN" = "yes" ] && SET_CAPABILITIES+=("CAP_CHOWN")
[ "$DOCKER_CAP_NET_RAW" = "yes" ] && SET_CAPABILITIES+=("CAP_NET_RAW")
[ "$DOCKER_CAP_SYS_NICE" = "yes" ] && SET_CAPABILITIES+=("CAP_SYS_NICE")
[ "$DOCKER_CAP_NET_ADMIN" = "yes" ] && SET_CAPABILITIES+=("CAP_NET_ADMIN")
[ "$DOCKER_CAP_NET_BIND_SERVICE" = "yes" ] && SET_CAPABILITIES+=("CAP_NET_BIND_SERVICE")
[ -n "${SET_CAPABILITIES[*]}" ] && CONTAINER_CAPABILITIES="${SET_CAPABILITIES[*]}"
if [ -n "$CONTAINER_CAPABILITIES" ]; then
  DOCKER_SET_CAP=""
  CONTAINER_CAPABILITIES="${CONTAINER_CAPABILITIES//,/ }"
  for cap in $CONTAINER_CAPABILITIES; do
    if [ "$cap" != "" ] && [ "$cap" != " " ]; then
      DOCKER_SET_CAP+="--cap-add $cap "
    fi
  done
  unset cap
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup sysctl
if [ -n "$CONTAINER_SYSCTL" ]; then
  DOCKER_SET_SYSCTL=""
  CONTAINER_SYSCTL="${CONTAINER_SYSCTL//,/ }"
  for sysctl in $CONTAINER_SYSCTL; do
    if [ "$sysctl" != "" ] && [ "$sysctl" != " " ]; then
      DOCKER_SET_SYSCTL+="--sysctl $sysctl "
    fi
  done
  unset sysctl
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup container labels
if [ -n "$CONTAINER_LABELS" ]; then
  DOCKER_SET_LABELS=""
  CONTAINER_LABELS="${CONTAINER_LABELS//,/ }"
  for label in $CONTAINER_LABELS; do
    if [ "$label" != "" ] && [ "$label" != " " ]; then
      DOCKER_SET_LABELS+="--label $label "
    fi
  done
  unset label
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup custom port mappings
SET_TEMP_LISTEN="${HOST_DEFINE_LISTEN//:*/}"
SET_TEMP_ADDR="${HOST_LISTEN_ADDR:-127.0.0.1}"
if [ -n "$CONTAINER_OPT_PORT_VAR" ] || [ -n "$CONTAINER_ADD_CUSTOM_PORT" ]; then
  SET_TEMP_PUBLISH=""
  CONTAINER_LISTEN_ON="${SET_TEMP_LISTEN:-$SET_TEMP_ADDR}"
  CONTAINER_OPT_PORT_VAR="${CONTAINER_OPT_PORT_VAR//,/ }"
  CONTAINER_ADD_CUSTOM_PORT="${CONTAINER_ADD_CUSTOM_PORT//,/ }"
  for set_port in $CONTAINER_ADD_CUSTOM_PORT $CONTAINER_OPT_PORT_VAR; do
    if [ "$set_port" != " " ] && [ -n "$set_port" ]; then
      new_port="${set_port//\/*/}"
      TYPE="$(echo "$set_port" | grep '/' | awk -F '/' '{print $NF}' | head -n1 | grep '^' || echo '')"
      if echo "$new_port" | grep -q 'random:'; then
        random_port="$(__rport)"
        new_port="${new_port//random:/}"
        port="$random_port:${new_port//*:/}"
      elif echo "$new_port" | grep -q ':.*[0-9]:[0-9]'; then
        port="$new_port"
        set_listen_addr="false"
      elif echo "$new_port" | grep -q ':'; then
        port="$new_port"
        set_listen_addr="true"
      else
        port="$new_port:$new_port"
        set_listen_addr="false"
      fi
      if [ "$CONTAINER_PRIVATE" = "yes" ]; then
        port="$SET_ADDR:$port"
      elif [ "$set_listen_addr" = "true" ]; then
        port="$CONTAINER_LISTEN_ON:$port"
      fi
      [ -z "$TYPE" ] && SET_TEMP_PUBLISH="$port" || SET_TEMP_PUBLISH="$port/$TYPE"
      DOCKER_SET_TMP_PUBLISH+=("--publish $SET_TEMP_PUBLISH")
    fi
  done
  unset set_port SET_TEMP_LISTEN SET_TEMP_ADDR SET_TEMP_PUBLISH
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# container web server configuration proxy|/location|port
if [ -n "$CONTAINER_ADD_RANDOM_PORTS" ] || { [ "$CONTAINER_WEB_SERVER_ENABLED" = "yes" ] && [ -n "$CONTAINER_WEB_SERVER_INT_PORT" ]; }; then
  CONTAINER_WEB_SERVER_LISTEN_ON="${CONTAINER_WEB_SERVER_LISTEN_ON:-}"
  CONTAINER_ADD_RANDOM_PORTS="${CONTAINER_ADD_RANDOM_PORTS//,/ }"
  CONTAINER_WEB_SERVER_INT_PORT="${CONTAINER_WEB_SERVER_INT_PORT//,/ }"
  for set_port in $CONTAINER_WEB_SERVER_INT_PORT $CONTAINER_ADD_RANDOM_PORTS; do
    if [ "$set_port" != " " ] && [ -n "$set_port" ]; then
      proxy_url=""
      proxy_location=""
      proxy_info="$set_port"
      get_port="${set_port//*|*|/}"
      port=${get_port//\/*/}
      port="${port//*:/}"
      random_port="$(__rport)"
      set_hostname="${proxy_info//|*/}"
      SET_WEB_PORT_TMP+=("$CONTAINER_WEB_SERVER_LISTEN_ON:$random_port")
      DOCKER_SET_TMP_PUBLISH+=("--publish $CONTAINER_WEB_SERVER_LISTEN_ON:$random_port:$port")
      if echo "$proxy_info" | grep -q '[a-zA-Z0-9]|/.*|[0-9]'; then
        NGINX_REPLACE_INCLUDE="yes"
        set_hostname="$(echo "$set_hostname" | grep -v 'proxy$' | grep '^' || false)"
        proxy_location="$(echo "$proxy_info" | awk -F '|' '{print $2}' | grep '^' || false)"
        proxy_url="$CONTAINER_WEB_SERVER_LISTEN_ON:$random_port"
        echo "$CONTAINER_PROTOCOL" | grep -q "^http" && nginx_proto="${CONTAINER_PROTOCOL:-http}" || nginx_proto="http"
        if [ -n "$proxy_url" ] && [ -n "$proxy_location" ]; then
          if [ -n "$set_hostname" ]; then
            NGINX_CUSTOM_CONFIG="true"
            echo "$set_hostname" | grep -qF '.' || set_hostname="$set_hostname.$CONTAINER_HOSTNAME"
            cat <<EOF | tee -a "$NGINX_VHOSTS_PROXY_FILE_TMP" &>/dev/null
server {
  listen                                    443 ssl http2;
  listen                                    [::]:443 ssl http2;
  server_name                               $set_hostname;
  access_log                                /var/log/nginx/access.$set_hostname.log;
  error_log                                 /var/log/nginx/error.$set_hostname.log info;
  keepalive_timeout                         75 75;
  client_max_body_size                      0;
  chunked_transfer_encoding                 on;
  add_header Strict-Transport-Security      "max-age=7200";
  ssl_protocols                             TLSv1.1 TLSv1.2;
  ssl_ciphers                               'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
  ssl_prefer_server_ciphers                 on;
  ssl_session_cache                         shared:SSL:10m;
  ssl_session_timeout                       1d;
  ssl_certificate                           /etc/letsencrypt/live/domain/fullchain.pem;
  ssl_certificate_key                       /etc/letsencrypt/live/domain/privkey.pem;

  include                                   /etc/nginx/global.d/nginx-defaults.conf;

  location $proxy_location {
    proxy_redirect                          http:// https://;
    proxy_pass                              $nginx_proto://$proxy_url;
    proxy_ssl_verify                        off;
    proxy_http_version                      1.1;
    proxy_connect_timeout                   3600;
    proxy_send_timeout                      3600;
    proxy_read_timeout                      3600;
    proxy_request_buffering                 off;
    proxy_buffering                         off;
    proxy_set_header                        Host               \$http_host;
    proxy_set_header                        X-Real-IP          \$remote_addr;
    proxy_set_header                        X-Forwarded-For    \$proxy_add_x_forwarded_for;
    proxy_set_header                        X-Forwarded-Proto  \$scheme;
    proxy_set_header                        Upgrade            \$http_upgrade;
    proxy_set_header                        Connection         \$connection_upgrade;
    send_timeout                            3600;
  }

}

EOF
          else
            cat <<EOF | tee -a "$NGINX_VHOSTS_INC_FILE_TMP" &>/dev/null
  location $proxy_location {
    proxy_redirect                          http:// https://;
    proxy_pass                              $nginx_proto://$proxy_url/;
    proxy_ssl_verify                        off;
    proxy_http_version                      1.1;
    proxy_connect_timeout                   3600;
    proxy_send_timeout                      3600;
    proxy_read_timeout                      3600;
    proxy_request_buffering                 off;
    proxy_buffering                         off;
    proxy_set_header                        Host              \$http_host;
    proxy_set_header                        X-Real-IP         \$remote_addr;
    proxy_set_header                        X-Forwarded-For   \$proxy_add_x_forwarded_for;
    proxy_set_header                        X-Forwarded-Proto \$scheme;
    proxy_set_header                        Upgrade           \$http_upgrade;
    proxy_set_header                        Connection        \$connection_upgrade;
    send_timeout                            3600;
  }

EOF
          fi
        fi
        unset proxy_info proxy_location proxy_url set_hostname
      fi
    fi
  done
  unset set_port CONTAINER_ADD_RANDOM_PORTS
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Fix/create port
SET_WEB_PORT="$(__trim "${SET_WEB_PORT_TMP[*]}")"
SET_NGINX_PROXY_PORT="$(echo "$SET_WEB_PORT" | tr ' ' '\n' | grep -v '^$' | head -n1 | grep '^' || echo '')"
if [ -n "$SET_NGINX_PROXY_PORT" ]; then
  CLEANUP_PORT="${SET_NGINX_PROXY_PORT//\/*/}"
  NGINX_PROXY_PORT="${CLEANUP_PORT//$NGINX_PROXY_ADDRESS:/}"
fi
unset SET_PRETTY_PORT SET_NGINX_PROXY_PORT SET_WEB_PORT_TMP CLEANUP_PORT
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# SSL setup
NGINX_PROXY_URL=""
PROXY_HTTP_PROTO="$CONTAINER_PROTOCOL"
if [ "$NGINX_SSL" = "yes" ]; then
  if [ "$SSL_ENABLED" = "yes" ]; then
    PROXY_HTTP_PROTO="https"
  fi
  if [ "$PROXY_HTTP_PROTO" = "https" ]; then
    NGINX_PROXY_URL="$PROXY_HTTP_PROTO://$NGINX_PROXY_ADDRESS:$NGINX_PROXY_PORT"
  fi
else
  CONTAINER_PROTOCOL="${CONTAINER_PROTOCOL:-http}"
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
NGINX_PROXY_URL="${NGINX_PROXY_URL:-$PROXY_HTTP_PROTO://$NGINX_PROXY_ADDRESS:$NGINX_PROXY_PORT}"
NGINX_PROXY_URL="${NGINX_PROXY_URL// /}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set temp env for PORTS ENV variable
CONTAINER_ENV_PORTS=("${DOCKER_SET_TMP_PUBLISH[@]//--publish/}")
SET_PORTS_ENV_TMP="$(__trim "${CONTAINER_ENV_PORTS[*]}")"
DOCKER_SET_PORTS_ENV_TMP="$(echo "${SET_PORTS_ENV_TMP//,/ }" | tr ' ' '\n' | grep ':' | awk -F ':' '{print $NF}' | grep '^')"
DOCKER_SET_PORTS_ENV_TMP="$(echo "$DOCKER_SET_PORTS_ENV_TMP" | grep '[0-9]' | sed 's|/.*||g' | sort -uV | grep -v '^$' | tr '\n' ' ' | grep '^' || echo '')"
ENV_PORTS="${DOCKER_SET_PORTS_ENV_TMP[*]}"
ENV_PORTS="$(__trim "${ENV_PORTS[*]}")"
if [ -n "$ENV_PORTS" ]; then
  DOCKER_SET_OPTIONS+=("--env ENV_PORTS=\"${ENV_PORTS[*]}\"")
fi
unset DOCKER_SET_PORTS_ENV_TMP ENV_PORTS SET_PORTS_ENV_TMP
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
DOCKER_CUSTOM_ARRAY="$(__custom_docker_env | grep '\--')"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Clean up variables
DOCKER_SET_PUBLISH="$(printf '%s\n' "${DOCKER_SET_TMP_PUBLISH[@]}" | sort -Vu | tr '\n' ' ')" # ensure only one
HUB_IMAGE_URL="$(__trim "${HUB_IMAGE_URL[*]:-}")"                                             # image url
HUB_IMAGE_TAG="$(__trim "${HUB_IMAGE_TAG[*]:-}")"                                             # image tag
DOCKER_GET_CAP="$(__trim "${DOCKER_SET_CAP[*]:-}")"                                           # --capabilites
DOCKER_GET_ENV="$(__trim "${DOCKER_SET_ENV[*]:-}")"                                           # --env
DOCKER_GET_DEV="$(__trim "${DOCKER_SET_DEV[*]:-}")"                                           # --device
DOCKER_GET_DNS="$(__trim "${DOCKER_SET_DNS[*]:-}")"                                           # --dns
DOCKER_GET_MNT="$(__trim "${DOCKER_SET_MNT[*]:-}")"                                           # --volume
DOCKER_GET_LINK="$(__trim "${DOCKER_SET_LINK[*]:-}")"                                         # --link
DOCKER_GET_LABELS="$(__trim "${DOCKER_SET_LABELS[*]:-}")"                                     # --labels
DOCKER_GET_SYSCTL="$(__trim "${DOCKER_SET_SYSCTL[*]:-}")"                                     # --sysctl
DOCKER_GET_OPTIONS="$(__trim "${DOCKER_SET_OPTIONS[*]:-}")"                                   # --env
DOCKER_GET_CUSTOM="$(__trim "${DOCKER_CUSTOM_ARRAY[*]:-}")"                                   # --tty --rm --interactive
DOCKER_GET_PUBLISH="$(__trim "${DOCKER_SET_PUBLISH[*]:-}")"                                   # --publish ports
CONTAINER_COMMANDS="$(__trim "${CONTAINER_COMMANDS[*]:-}")"                                   # pass command to container
[ -n "$CONTAINER_COMMANDS" ] || CONTAINER_COMMANDS="    "
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# set docker commands - script creation - execute command #
SET_EXECUTE_PRE_INSTALL="$(echo "docker stop $CONTAINER_NAME;docker rm -f $CONTAINER_NAME;docker pull $HUB_IMAGE_URL:$HUB_IMAGE_TAG ")"
SET_EXECUTE_DOCKER_CMD="$(echo "docker run -d $DOCKER_GET_OPTIONS $DOCKER_GET_CUSTOM $DOCKER_GET_LINK $DOCKER_GET_LABELS $DOCKER_GET_CAP $DOCKER_GET_SYSCTL $DOCKER_GET_DEV $DOCKER_SET_DNS $DOCKER_GET_MNT $DOCKER_GET_ENV $DOCKER_GET_PUBLISH $HUB_IMAGE_URL:$HUB_IMAGE_TAG $CONTAINER_COMMANDS")"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Run functions
__container_import_variables "$CONTAINER_ENV_FILE_MOUNT"
__dockermgr_variables >"$DOCKERMGR_CONFIG_DIR/env/$APPNAME.conf"
__dockermgr_password_variables >"$DOCKERMGR_CONFIG_DIR/secure/$APPNAME"
chmod -f 600 "$DOCKERMGR_CONFIG_DIR/secure/$APPNAME"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
__custom_docker_env | tr ' ' '\n' | sed 's|^--.*||g' | grep -v '^$' >"$DOCKERMGR_CONFIG_DIR/env/$APPNAME.custom.conf"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Main progam
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
[ -d "$APPDIR/files" ] && { [ ! -d "$DATADIR" ] && mv -f "$APPDIR/files" "$DATADIR"; }
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Clone/update the repo
if __am_i_online; then
  urlverify "$REPO" || printf_exit "$REPO was not found"
  if [ -d "$INSTDIR/.git" ]; then
    message="Updating $APPNAME configurations"
    execute "git_update $INSTDIR" "$message"
  else
    message="Installing $APPNAME configurations"
    execute "git_clone $REPO $INSTDIR" "$message"
  fi
  # exit on fail
  failexitcode $? "$message has failed"
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Write the container name to file
echo "$CONTAINER_NAME" >"$DOCKERMGR_CONFIG_DIR/installed/$APPNAME"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if [ ! -d "$DATADIR" ]; then
  mkdir -p "$DATADIR"
  chmod -f 777 "$DATADIR"
fi
if [ ! -d "$LOCAL_DATA_DIR" ]; then
  mkdir -p "$LOCAL_DATA_DIR"
  chmod -f 777 "$LOCAL_DATA_DIR"
fi
if [ ! -d "$LOCAL_CONFIG_DIR" ]; then
  mkdir -p "$LOCAL_CONFIG_DIR"
  chmod -f 777 "$LOCAL_CONFIG_DIR"
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
CONTAINER_CREATE_DIRECTORY="${CONTAINER_CREATE_DIRECTORY//,/ }"
CONTAINER_CREATE_DIRECTORY="$(__trim "$CONTAINER_CREATE_DIRECTORY")"
if [ -n "$CONTAINER_CREATE_DIRECTORY" ]; then
  CONTAINER_CREATE_DIRECTORY="${CONTAINER_CREATE_DIRECTORY//, /}"
  for dir in $CONTAINER_CREATE_DIRECTORY; do
    if [ -n "$dir" ] && [ ! -d "$DATADIR/$dir" ]; then
      mkdir -p "$DATADIR/$dir"
      chmod -f 777 "$DATADIR/$dir"
    fi
  done
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Copy over data files - keep the same stucture as -v DATADIR/mnt:/mnt
if [ -d "$INSTDIR/rootfs" ] && [ ! -f "$DATADIR/.installed" ]; then
  printf_yellow "Copying files to $DATADIR"
  __sudo_exec cp -Rf "$INSTDIR/rootfs/." "$DATADIR/" &>/dev/null
  find "$DATADIR" -name ".gitkeep" -type f -exec rm -rf {} \; &>/dev/null
fi
if [ -f "$DATADIR/.installed" ]; then
  __sudo_exec date +'Updated on %Y-%m-%d at %H:%M' | tee "$DATADIR/.installed" &>/dev/null
else
  __sudo_exec chown -Rf "$USER":"$USER" "$DOCKERMGR_CONFIG_DIR" &>/dev/null
  __sudo_exec chown -f "$USER":"$USER" "$DATADIR" "$INSTDIR" "$INSTDIR" &>/dev/null
  __sudo_exec date +'installed on %Y-%m-%d at %H:%M' | tee "$DATADIR/.installed" &>/dev/null
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Mount /etc/resolv.conf file in the container
if [ "$HOST_RESOLVE_ENABLED" = "yes" ]; then
  mkdir -p "$INSTDIR/rootfs/etc"
  [ -n "$HOST_ETC_RESOLVE_INIT_FILE" ] || HOST_ETC_RESOLVE_INIT_FILE="/etc/resolv.conf"
  if [ ! -f "$INSTDIR/rootfs/etc/resolv.conf" ]; then
    cp -Rf "$HOST_ETC_RESOLVE_INIT_FILE" "$INSTDIR/rootfs/etc/resolv.conf"
  fi
  touch "$INSTDIR/rootfs/etc/resolv.conf"
  if [ "$HOST_ETC_RESOLVE_INIT_FILE" = "/usr/local/etc/resolv.conf" ]; then
    DOCKER_SET_OPTIONS+=("--volume $INSTDIR/rootfs/etc/resolv.conf:/usr/local/etc/resolv.conf")
  else
    DOCKER_SET_OPTIONS+=("--volume $INSTDIR/rootfs/etc/resolv.conf:/etc/resolv.conf")
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Mount /etc/hosts file in the container
if [ "$HOST_ETC_HOSTS_ENABLED" = "yes" ]; then
  mkdir -p "$INSTDIR/rootfs/etc"
  [ -n "$HOST_ETC_HOSTS_INIT_FILE" ] || HOST_ETC_HOSTS_INIT_FILE="/etc/hosts"
  if [ ! -f "$INSTDIR/rootfs/etc/hosts" ]; then
    cp -Rf "$HOST_ETC_HOSTS_INIT_FILE" "$INSTDIR/rootfs/etc/hosts"
  fi
  touch "$INSTDIR/rootfs/etc/hosts"
  if [ "$HOST_ETC_HOSTS_INIT_FILE" = "/usr/local/etc/hosts" ]; then
    DOCKER_SET_OPTIONS+=("--volume $INSTDIR/rootfs/etc/hosts:/usr/local/etc/hosts")
  else
    DOCKER_SET_OPTIONS+=("--volume $INSTDIR/rootfs/etc/hosts:/etc/hosts")
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
DOCKERMGR_INSTALL_SCRIPT="$DOCKERMGR_CONFIG_DIR/scripts/$CONTAINER_NAME.sh"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# setup the container
unset EXECUTE_DOCKER_SCRIPT
EXECUTE_DOCKER_CMD="$(__trim "${SET_EXECUTE_DOCKER_CMD[*]}")"
EXECUTE_PRE_INSTALL="$(__trim "${SET_EXECUTE_PRE_INSTALL[*]}")"
DOCKER_COMPOSE_CMD="$(docker compose 2>&1 | grep -q 'is not a docker command.' || echo "true")"
if [ "$DOCKER_COMPOSE_CMD" = "true" ] && [ -f "$INSTDIR/docker-compose.yml" ]; then
  printf_yellow "Installing containers using docker-compose"
  sed -i 's|REPLACE_DATADIR|'$DATADIR'' "$INSTDIR/docker-compose.yml" &>/dev/null
  if cd "$INSTDIR"; then
    docker compose pull &>/dev/null
    docker compose up -d &>/dev/null
    CONTAINER_INSTALLED="true"
    create_docker_script_message_pre="Failed to cd into $INSTDIR"
    create_docker_script_message_post="Failed to bring up containers"
    EXECUTE_PRE_INSTALL="$(echo 'cd "'$INSTDIR'"')"
    EXECUTE_DOCKER_CMD="$(echo 'docker compose pull && docker compose up -d')"
  fi
elif [ -n "$(type -P docker-compose)" ] && [ -f "$INSTDIR/docker-compose.yml" ]; then
  printf_yellow "Installing containers using docker-compose"
  sed -i 's|REPLACE_DATADIR|'$DATADIR'' "$INSTDIR/docker-compose.yml" &>/dev/null
  if cd "$INSTDIR"; then
    docker-compose pull &>/dev/null
    docker-compose up -d &>/dev/null
    CONTAINER_INSTALLED="true"
    create_docker_script_message_pre="Failed to cd into $INSTDIR"
    create_docker_script_message_post="Failed to bring up containers"
    EXECUTE_PRE_INSTALL="$(echo 'cd "'$INSTDIR'"')"
    EXECUTE_DOCKER_CMD="$(echo 'docker-compose pull && docker-compose up -d')"
  fi
fi
__create_docker_script
EXECUTE_DOCKER_SCRIPT="$EXECUTE_DOCKER_CMD"
if [ -n "$EXECUTE_DOCKER_SCRIPT" ]; then
  EXECUTE_PRE_INSTALL="$(__trim "${EXECUTE_PRE_INSTALL//||*/}")"
  EXECUTE_DOCKER_SCRIPT="$(__trim "${EXECUTE_DOCKER_SCRIPT//||*/}")"
  printf_cyan "Updating the image from $HUB_IMAGE_URL with tag $HUB_IMAGE_TAG"
  eval "$EXECUTE_PRE_INSTALL" 2>"${TMP:-/tmp}/$APPNAME.err.log" >/dev/null
  printf_cyan "Creating container $CONTAINER_NAME"
  if eval $EXECUTE_DOCKER_SCRIPT 1>/dev/null 2>"${TMP:-/tmp}/$APPNAME.err.log"; then
    sleep 10
    __container_is_running || __sudo_exec docker start $CONTAINER_NAME &>/dev/null
    rm -Rf "${TMP:-/tmp}/$APPNAME.err.log"
    echo "$CONTAINER_NAME" >"$DOCKERMGR_CONFIG_DIR/containers/$APPNAME"
    __docker_ps_all -q && CONTAINER_INSTALLED="true"
  else
    ERROR_LOG="true"
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Install nginx proxy
NINGX_VHOSTS_WRITABLE="$(sudo -n true && sudo bash -c 'mkdir -p "$NGINX_DIR/vhosts.d";[ -w "$NGINX_DIR/vhosts.d" ] && echo "true" || false' || echo 'false')"
if [ "$NINGX_VHOSTS_WRITABLE" = "true" ]; then
  NGINX_VHOST_TMP_NAMES=()
  NGINX_VHOST_ENABLED="true"
  NGINX_VHOST_SET_NAMES="${CONTAINER_WEB_SERVER_VHOSTS//,/ }"
  NGINX_CONFIG_NAME="${CONTAINER_WEB_SERVER_CONFIG_NAME:-$CONTAINER_HOSTNAME}"
  NGINX_MAIN_CONFIG="$NGINX_DIR/vhosts.d/$NGINX_CONFIG_NAME.conf"
  NGINX_VHOST_CONFIG="$NGINX_DIR/vhosts.d/$NGINX_CONFIG_NAME.custom.conf"
  NGINX_INC_CONFIG="$NGINX_DIR/conf.d/vhosts/$NGINX_CONFIG_NAME.conf"
  [ -d "$NGINX_DIR/conf.d/vhosts" ] || __sudo_root mkdir -p "$NGINX_DIR/conf.d/vhosts"
  if [ "$HOST_NGINX_UPDATE_CONF" = "yes" ] && [ -f "$INSTDIR/nginx/proxy.conf" ]; then
    for vhost in $NGINX_VHOST_SET_NAMES; do
      if [ -n "$vhost" ]; then
        if echo "$vhost" | grep -q '^[.]*'; then
          NGINX_VHOST_TMP_NAMES+=("*.$CONTAINER_HOSTNAME")
        elif echo "$vhost" | grep -q "[.]all$"; then
          NGINX_VHOST_TMP_NAMES+=("${vhost//.all/}.*")
        elif echo "$vhost" | grep -q '[.]myhostname$'; then
          NGINX_VHOST_TMP_NAMES+=("${vhost//.mydomain/}.$CONTAINER_HOSTNAME")
        elif echo "$vhost" | grep -q '[.]mydomain$'; then
          NGINX_VHOST_TMP_NAMES+=("${vhost//.mydomain/}.${CONTAINER_DOMAINNAME:-$CONTAINER_HOSTNAME}")
        else
          NGINX_VHOST_TMP_NAMES+=("$vhost")
        fi
      fi
    done
    if [ -n "${NGINX_VHOST_TMP_NAMES[*]}" ]; then
      NGINX_VHOST_NAMES="$(__trim "${NGINX_VHOST_TMP_NAMES[*]}")"
      CONTAINER_WEB_SERVER_VHOSTS="$NGINX_VHOST_NAMES"
      unset NGINX_VHOST_TMP_NAMES
    else
      NGINX_VHOST_NAMES="${NGINX_VHOST_NAMES:-}"
    fi
    cp -f "$INSTDIR/nginx/proxy.conf" "$NGINX_VHOSTS_CONF_FILE_TMP"
    sed -i "s|REPLACE_APPNAME|$APPNAME|g" "$NGINX_VHOSTS_CONF_FILE_TMP" &>/dev/null
    sed -i "s|REPLACE_NGINX_PORT|$NGINX_PORT|g" "$NGINX_VHOSTS_CONF_FILE_TMP" &>/dev/null
    sed -i "s|REPLACE_HOST_PROXY|$NGINX_PROXY_URL|g" "$NGINX_VHOSTS_CONF_FILE_TMP" &>/dev/null
    sed -i "s|REPLACE_NGINX_HOST|$CONTAINER_HOSTNAME|g" "$NGINX_VHOSTS_CONF_FILE_TMP" &>/dev/null
    sed -i "s|REPLACE_NGINX_VHOSTS|$NGINX_VHOST_NAMES|g" "$NGINX_VHOSTS_CONF_FILE_TMP" &>/dev/null
    sed -i "s|REPLACE_SERVER_LISTEN_OPTS|$NGINX_LISTEN_OPTS|g" "$NGINX_VHOSTS_CONF_FILE_TMP" &>/dev/null
    if [ -d "$NGINX_DIR/vhosts.d" ]; then
      if [ -f "$NGINX_VHOSTS_INC_FILE_TMP" ]; then
        sed -i "s|REPLACE_NGINX_INCLUDE|$NGINX_INC_CONFIG|g" "$NGINX_VHOSTS_CONF_FILE_TMP"
        __sudo_root mv -f "$NGINX_VHOSTS_INC_FILE_TMP" "$NGINX_INC_CONFIG"
      elif [ -f "$INSTDIR/nginx/conf.d/vhosts/include.conf" ]; then
        cat "$INSTDIR/nginx/conf.d/vhosts/include.conf" | tee "$NGINX_VHOSTS_INC_FILE_TMP" &>/dev/null
        sed -i "s|REPLACE_NGINX_INCLUDE|$NGINX_INC_CONFIG|g" "$NGINX_VHOSTS_CONF_FILE_TMP"
        __sudo_root mv -f "$NGINX_VHOSTS_INC_FILE_TMP" "$NGINX_INC_CONFIG"
      fi
      if [ -f "$NGINX_VHOSTS_PROXY_FILE_TMP" ] && [ "$NGINX_CUSTOM_CONFIG" = "true" ]; then
        __sudo_root mv -f "$NGINX_VHOSTS_PROXY_FILE_TMP" "$NGINX_VHOST_CONFIG"
      fi
      if [ ! -f "$NGINX_INC_CONFIG" ]; then
        sed -i "s|include.*REPLACE_NGINX_INCLUDE;||g" "$NGINX_VHOSTS_CONF_FILE_TMP"
      fi
      __sudo_root mv -f "$NGINX_VHOSTS_CONF_FILE_TMP" "$NGINX_MAIN_CONFIG"
      if [ -f "$NGINX_MAIN_CONFIG" ]; then
        NGINX_IS_INSTALLED="yes"
        NGINX_CONF_FILE="$NGINX_MAIN_CONFIG"
      fi
      if [ -f "/etc/nginx/nginx.conf" ]; then
        systemctl status nginx 2>/dev/null | grep -q enabled &>/dev/null && __sudo_root systemctl reload nginx &>/dev/null
      fi
    else
      mv -f "$NGINX_VHOSTS_CONF_FILE_TMP" "$INSTDIR/nginx/$NGINX_CONFIG_NAME.conf" &>/dev/null
    fi
  else
    NGINX_PROXY_URL=""
  fi
  [ -f "$NGINX_MAIN_CONFIG" ] && NGINX_PROXY_URL="$CONTAINER_PROTOCOL://$CONTAINER_HOSTNAME"
fi
{ [ "$NGINX_VHOST_NAMES" = "" ] || [ "$NGINX_VHOST_NAMES" = " " ]; } && unset NGINX_VHOST_NAMES
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# finalize
if [ "$CONTAINER_INSTALLED" = "true" ] || __docker_ps_all -q; then
  DOCKER_PORTS="$(__trim "${DOCKER_GET_PUBLISH//--publish/}")"
  SET_PORT="$(echo "$DOCKER_PORTS" | tr ' ' '\n' | grep -vE '^$|--' | sort -V | awk -F ':' '{print $1":"$3":"$2}' | grep '^')"
  HOSTS_WRITABLE="$(sudo -n true && sudo bash -c '[ -w "/etc/hosts" ] && echo "true" || false' || echo 'false')"
  printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  if [ "$HOSTS_WRITABLE" = "true" ]; then
    if [ "$HOST_LISTEN_ADDR" = 'home' ]; then
      __printf_color "44" "Adding to /etc/hosts:                   $APPNAME.home $HOST_LISTEN_ADDR"
      if ! grep -sq " $APPNAME.home" "/etc/hosts"; then
        echo "$HOST_LISTEN_ADDR        $APPNAME.home" | sudo tee -a "/etc/hosts" &>/dev/null
      fi
    else
      __printf_color "44" "Adding to /etc/hosts:                   $APPNAME.home $HOST_LISTEN_ADDR"
      if ! grep -sq " $APPNAME.home" "/etc/hosts"; then
        echo "$HOST_LISTEN_ADDR        $APPNAME.home" | sudo tee -a "/etc/hosts" &>/dev/null
      fi
      __printf_color "44" "Adding to /etc/hosts:                   $CONTAINER_HOSTNAME $HOST_LISTEN_ADDR"
      if ! grep -sq " $CONTAINER_HOSTNAME" "/etc/hosts"; then
        echo "$HOST_LISTEN_ADDR        $CONTAINER_HOSTNAME" | sudo tee -a "/etc/hosts" &>/dev/null
      fi
      show_hosts_messge_banner="true"
    fi
    if [ -n "$NGINX_VHOST_NAMES" ]; then
      NGINX_VHOST_NAMES="${NGINX_VHOST_NAMES//,/ }"
      for vhost in $NGINX_VHOST_NAMES; do
        if ! grep -sq " $vhost" "/etc/hosts"; then
          if echo "$vhost" | grep -qFv '*'; then
            __printf_color "44" "Adding to /etc/hosts:                  $vhost $CONTAINER_WEB_SERVER_LISTEN_ON"
            echo "$CONTAINER_WEB_SERVER_LISTEN_ON        $vhost" | sudo tee -a "/etc/hosts" &>/dev/null
          fi
        fi
      done
      show_hosts_messge_banner="true"
    fi
    [ "$show_hosts_messge_banner" = "true" ] && printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
    unset show_hosts_messge_banner
  fi
  printf_yellow "The container name is:                  $CONTAINER_NAME"
  printf_yellow "The container is listening on:          $HOST_LISTEN_ADDR"
  printf_yellow "The hostname name is set to:            $CONTAINER_HOSTNAME"
  printf_yellow "Containers data is saved in:            $DATADIR"
  printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  if __ssl_certs; then
    mkdir -p "$CONTAINER_SSL_DIR"
    __sudo_exec chmod -f 777 "$CONTAINER_SSL_DIR"
    if __sudo_exec cp -Rf "$HOST_SSL_CA" "$CONTAINER_SSL_CA"; then
      __sudo_exec chmod -Rf 666 "$CONTAINER_SSL_CA"
      printf_yellow "Copied CA Cert to:                      $CONTAINER_SSL_CA"
    fi
    if __sudo_exec cp -Rf "$HOST_SSL_CRT" "$CONTAINER_SSL_CRT"; then
      __sudo_exec chmod -Rf 666 "$CONTAINER_SSL_DIR"
      printf_yellow "Copied certificate to:                  $CONTAINER_SSL_CRT"
    fi
    if __sudo_exec cp -Rf "$HOST_SSL_KEY" "$CONTAINER_SSL_KEY"; then
      __sudo_exec chmod -Rf 666 "$CONTAINER_SSL_DIR"
      printf_yellow "Copied private key to:                  $CONTAINER_SSL_KEY"
    fi
    __sudo_exec chown -Rf "$USER":"$USER" "$CONTAINER_SSL_DIR" &>/dev/null
    printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  fi
  if [ "$DOCKER_CREATE_NET" ]; then
    printf_purple "Created docker network:                 $HOST_DOCKER_NETWORK"
    printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  fi
  if [ "$NGINX_IS_INSTALLED" = "yes" ]; then
    printf_cyan "nginx vhost name:                       $CONTAINER_HOSTNAME"
    printf_cyan "nginx website:                          $NGINX_PROXY_URL"
    if [ -f "$NGINX_CONF_FILE" ]; then
      printf_cyan "nginx config file installed to:         $NGINX_CONF_FILE"
    fi
    if [ -f "$NGINX_INC_CONFIG" ]; then
      printf_cyan "nginx vhost file installed to:          $NGINX_INC_CONFIG"
    fi
    if [ -f "$NGINX_VHOST_CONFIG" ]; then
      printf_cyan "nginx custom vhost file installed to:   $NGINX_VHOST_CONFIG"
    fi
    printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  fi
  if [ -n "$SET_PORT" ] && [ -n "$NGINX_PROXY_URL" ]; then
    MESSAGE="true"
    printf_blue "Server address:                         $NGINX_PROXY_URL"
    if [ -n "$NGINX_VHOST_NAMES" ]; then
      NGINX_VHOST_NAMES="${NGINX_VHOST_NAMES//,/ }"
      for vhost in $NGINX_VHOST_NAMES; do
        printf_blue "vhost name:                             $vhost"
      done
    fi
    printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  fi
  if [ -n "$CONTAINER_USER_NAME" ]; then
    show_user_footer="true"
    printf_cyan "Username is:                            $CONTAINER_USER_NAME"
  fi
  if [ -n "$CONTAINER_USER_PASS" ]; then
    show_user_footer="true"
    printf_blue "Password is:                            $CONTAINER_USER_PASS"
  fi
  if [ "$CONTAINER_DATABASE_USER_ROOT" ]; then
    show_user_footer="true"
    printf_blue "Database root user:                     $CONTAINER_DATABASE_USER_ROOT"
  fi
  if [ "$CONTAINER_DATABASE_PASS_ROOT" ]; then
    show_user_footer="true"
    printf_blue "Database root password:                 $CONTAINER_DATABASE_PASS_ROOT"
  fi
  if [ "$CONTAINER_DATABASE_USER_NORMAL" ]; then
    show_user_footer="true"
    printf_blue "Database user:                          $CONTAINER_DATABASE_USER_NORMAL"
  fi
  if [ "$CONTAINER_DATABASE_PASS_NORMAL" ]; then
    show_user_footer="true"
    printf_blue "Database password:                     $CONTAINER_DATABASE_PASS_NORMAL"
  fi
  [ "$show_user_footer" = "true" ] && printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  if [ "$SHOW_DATABASE_INFO" = "true" ]; then
    printf_yellow "Database is running on:                 $CONTAINER_DATABASE_PROTO"
    if [ -n "$MESSAGE_CONTAINER_DATABASE" ]; then
      printf_cyan "$MESSAGE_CONTAINER_DATABASE"
    fi
    if [ -n "$MESSAGE_COUCHDB" ]; then
      printf_cyan "$MESSAGE_COUCHDB"
    fi
    if [ -n "$MESSAGE_SQLITE3" ]; then
      printf_cyan "$MESSAGE_SQLITE3"
    fi
    if [ -n "$MESSAGE_MARIADB" ]; then
      printf_cyan "$MESSAGE_MARIADB"
    fi
    if [ -n "$MESSAGE_MONGODB" ]; then
      printf_cyan "$MESSAGE_MONGODB"
    fi
    if [ -n "$MESSAGE_PGSQL" ]; then
      printf_cyan "$MESSAGE_PGSQL"
    fi
    if [ -n "$MESSAGE_REDIS" ]; then
      printf_cyan "$MESSAGE_REDIS"
    fi
    if [ -n "$MESSAGE_SUPABASE" ]; then
      printf_cyan "$MESSAGE_SUPABASE"
    fi
    printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  fi
  if [ -f "$DATADIR/config/auth/htpasswd" ]; then
    MESSAGE="true"
    printf_purple "Username:                               root"
    printf_purple "Password:                               ${SET_USER_PASS:-toor}"
    printf_purple "htpasswd File:                          /config/auth/htpasswd"
    printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  fi
  if [ -z "$SET_PORT" ]; then
    printf_yellow "This container does not have services configured"
    printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  else
    for service in $SET_PORT; do
      if [ "$service" != "--publish" ] && [ "$service" != " " ] && [ -n "$service" ]; then
        type=""
        if echo "$service" | grep -q ":.*.:"; then
          set_host="$(echo "$service" | awk -F ':' '{print $1}')"
          set_port="$(echo "$service" | awk -F ':' '{print $3}')"
          set_service="$(echo "$service" | awk -F ':' '{print $2}')"
        else
          set_host="$SET_LISTEN"
          set_port="$(echo "$service" | awk -F ':' '{print $1}')"
          set_service="$(echo "$service" | awk -F ':' '{print $2}')"
        fi
        get_servive="$set_service"
        set_service="${set_service//\/*/}"
        characters=${#set_service}
        spacing=$((40 - 19 - characters))
        listen="${set_host//0.0.0.0/$HOST_LISTEN_ADDR}:$set_port"
        echo "$get_servive" | grep -qE '[0-9]/tcp|[0-9]/udp' && type="${get_servive//*\//}" || unset type
        [ -n "$type" ] && get_listen="$listen/$type" || get_listen="$listen"
        set_listen=$(printf "%-${spacing}s" "" "$get_listen")
        if [ -n "$listen" ]; then
          printf_cyan "Port $set_service is mapped to:$set_listen"
        fi
      fi
      unset characters spacing get_listen type
    done
    printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  fi
  if [ -f "$DOCKERMGR_INSTALL_SCRIPT" ]; then
    printf_yellow "Script saved to:                        $DOCKERMGR_INSTALL_SCRIPT"
    printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  fi
  if [ -f "$DOCKERMGR_CONFIG_DIR/env/$APPNAME.conf" ] || [ -f "$DOCKERMGR_CONFIG_DIR/env/$APPNAME.custom.conf" ]; then
    if [ -f "$DOCKERMGR_CONFIG_DIR/env/$APPNAME.conf" ]; then
      printf_green "variables saved to:                     $DOCKERMGR_CONFIG_DIR/env/$APPNAME.conf"
    fi
    if [ -f "$DOCKERMGR_CONFIG_DIR/env/$APPNAME.custom.conf" ]; then
      printf_green "Container variables saved to:           $DOCKERMGR_CONFIG_DIR/env/$APPNAME.custom.conf"
    fi
    printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  fi
  if [ -n "$POST_SHOW_FINISHED_MESSAGE" ]; then
    printf_green "$POST_SHOW_FINISHED_MESSAGE"
    printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
  fi
  characters=${#APPNAME}
  spacing=$((characters))
  install_dir=$(printf "%-${spacing}s" "" "$APPDIR")
  printf_cyan "$APPNAME has been installed to:   $install_dir"
  printf '# - - - - - - - - - - - - - - - - - - - - - - - - - -\n\n'
  __show_post_message
else
  printf_cyan "The container $CONTAINER_NAME seems to have failed"
  if [ "$ERROR_LOG" = "true" ]; then
    printf_yellow "Errors logged to: ${TMP:-/tmp}/$APPNAME.err.log"
  else
    printf_red "Something seems to have gone wrong with the install"
  fi
  if [ -f "$DOCKERMGR_INSTALL_SCRIPT" ]; then
    printf_yellow "Script: $DOCKERMGR_INSTALL_SCRIPT"
  fi
  exit 10
fi
if [ "$USER" != "root" ] && [ -n "$USER" ]; then
  __sudo_exec chown -f "$USER":"$USER" "$DATADIR" "$INSTDIR" &>/dev/null
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# run post install scripts
run_postinst() {
  dockermgr_run_post
}
#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# run post install scripts
execute "run_postinst" "Running post install scripts" 1>/dev/null
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Output post install message
run_post_install &>/dev/null
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# create version file
dockermgr_install_version &>/dev/null
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# exit
run_exit >/dev/null
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# End application
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# lets exit with code
exit ${EXIT:-${exitCode:-0}}
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# ex: ts=2 sw=2 et filetype=sh
