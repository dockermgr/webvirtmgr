#!/usr/bin/env bash
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
APPNAME="webvirtmgr"
USER="${SUDO_USER:-${USER}}"
HOME="${USER_HOME:-${HOME}}"
SRC_DIR="${BASH_SOURCE%/*}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Set bash options
if [[ "$1" == "--debug" ]]; then shift 1 && set -xo pipefail && export SCRIPT_OPTS="--debug" && export _DEBUG="on"; fi

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
##@Version       : 202108282020-git
# @Author        : Jason Hempstead
# @Contact       : jason@casjaysdev.com
# @License       : WTFPL
# @ReadME        : webvirtmgr --help
# @Copyright     : Copyright: (c) 2021 Jason Hempstead, Casjays Developments
# @Created       : Saturday, Aug 28, 2021 20:20 EDT
# @File          : webvirtmgr
# @Description   :
# @TODO          :
# @Other         :
# @Resource      :
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Import functions
CASJAYSDEVDIR="${CASJAYSDEVDIR:-/usr/local/share/CasjaysDev/scripts}"
SCRIPTSFUNCTDIR="${CASJAYSDEVDIR:-/usr/local/share/CasjaysDev/scripts}/functions"
SCRIPTSFUNCTFILE="${SCRIPTSAPPFUNCTFILE:-app-installer.bash}"
SCRIPTSFUNCTURL="${SCRIPTSAPPFUNCTURL:-https://github.com/dfmgr/installer/raw/main/functions}"
connect_test() { ping -c1 1.1.1.1 &>/dev/null || curl --disable -LSs --connect-timeout 3 --retry 0 --max-time 1 1.1.1.1 2>/dev/null | grep -e "HTTP/[0123456789]" | grep -q "200" -n1 &>/dev/null; }
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
if [ -f "$PWD/$SCRIPTSFUNCTFILE" ]; then
  . "$PWD/$SCRIPTSFUNCTFILE"
elif [ -f "$SCRIPTSFUNCTDIR/$SCRIPTSFUNCTFILE" ]; then
  . "$SCRIPTSFUNCTDIR/$SCRIPTSFUNCTFILE"
elif connect_test; then
  curl -LSs "$SCRIPTSFUNCTURL/$SCRIPTSFUNCTFILE" -o "/tmp/$SCRIPTSFUNCTFILE" || exit 1
  . "/tmp/$SCRIPTSFUNCTFILE"
else
  echo "Can not load the functions file: $SCRIPTSFUNCTDIR/$SCRIPTSFUNCTFILE" 1>&2
  exit 1
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Call the main function
user_installdirs
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Define extra functions
__sudo() { if sudo -n true; then eval sudo "$*"; else eval "$*"; fi; }
__sudo_root() { sudo -n true && ask_for_password true && eval sudo "$*" || return 1; }
__enable_ssl() { [[ "$SERVER_SSL" = "yes" ]] && [[ "$SERVER_SSL" = "true" ]] && return 0 || return 1; }
__ssl_certs() { [ -f "${1:-$SERVER_SSL_CRT}" ] && [ -f "${2:-SERVER_SSL_KEY}" ] && return 0 || return 1; }
__port_not_in_use() { [[ -d "/etc/nginx/vhosts.d" ]] && grep -wRsq "${1:-$SERVER_PORT}" /etc/nginx/vhosts.d && return 0 || return 1; }
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Make sure the scripts repo is installed
scripts_check
REPO_BRANCH="${GIT_REPO_BRANCH:-master}"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Defaults
APPNAME="webvirtmgr"
APPDIR="$HOME/.local/share/srv/docker/webvirtmgr"
DATADIR="$HOME/.local/share/srv/docker/webvirtmgr/files"
INSTDIR="$HOME/.local/share/dockermgr/webvirtmgr"
REPO="${DOCKERMGRREPO:-https://github.com/dockermgr}/webvirtmgr"
REPORAW="$REPO/raw/$REPO_BRANCH"
APPVERSION="$(__appversion "$REPORAW/version.txt")"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Setup plugins
HUB_URL="flexible1983/webvirtmgr-docker"
NGINX_HTTP="${NGINX_HTTP:-80}"
NGINX_HTTPS="${NGINX_HTTPS:-443}"
SERVER_IP="${CURRIP4:-127.0.0.1}"
SERVER_LISTEN="${SERVER_LISTEN:-0.0.0.0}"
SERVER_HOST="${APPNAME}.$(hostname -d 2>/dev/null | grep '^' || echo local)"
SERVER_PORT="${SERVER_PORT:-14020}"
SERVER_PORT_INT="${SERVER_PORT_INT:-8080}"
SERVER_PORT_ADMIN="${SERVER_PORT_ADMIN:-}"
SERVER_PORT_ADMIN_INT="${SERVER_PORT_ADMIN_INT:-}"
SERVER_PORT_OTHER="${SERVER_PORT_OTHER:-6080}"
SERVER_PORT_OTHER_INT="${SERVER_PORT_OTHER_INT:-6080}"
SERVER_TIMEZONE="${TZ:-${TIMEZONE:-America/New_York}}"
SERVER_SSL_CRT="/etc/ssl/CA/CasjaysDev/certs/localhost.crt"
SERVER_SSL_KEY="/etc/ssl/CA/CasjaysDev/private/localhost.key"
[[ -f "$SERVER_SSL_CRT" ]] && [[ -f "$SERVER_SSL_KEY" ]] && SERVER_SSL="true"
[[ -n "$SERVER_SSL" ]] || SERVER_SSL="${SERVER_SSL:-false}"

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Require a version higher than
dockermgr_req_version "$APPVERSION"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Call the dockermgr function
dockermgr_install
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Script options IE: --help
show_optvars "$@"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Requires root - no point in continuing
#sudoreq "$0 $*" # sudo required
#sudorun # sudo optional
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Do not update - add --force to overwrite
#installer_noupdate "$@"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# initialize the installer
dockermgr_run_init
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Ensure directories exist
ensure_dirs
ensure_perms
mkdir -p "$DATADIR/data"
mkdir -p "$DATADIR/config"
chmod -Rf 777 "$APPDIR"

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Clone/update the repo
if am_i_online; then
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
# Copy over data files - keep the same stucture as -v dataDir/mnt:/mount
if [[ -d "$INSTDIR/dataDir" ]] && [[ ! -f "$DATADIR/.installed" ]]; then
  printf_blue "Copying files to $DATADIR"
  cp -Rf "$INSTDIR/dataDir/." "$DATADIR/"
  touch "$DATADIR/.installed"
  find "$DATADIR" -name ".gitkeep" -type f -exec rm -rf {} \; &>/dev/null
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Main progam
if [ -f "$INSTDIR/docker-compose.yml" ] && cmd_exists docker-compose; then
  printf_blue "Installing containers using dockercompose"
  sed -i "s|REPLACE_DATADIR|$DATADIR" "$INSTDIR/docker-compose.yml"
  if cd "$INSTDIR"; then
    __sudo docker-compose pull &>/dev/null
    __sudo docker-compose up -d &>/dev/null
  fi
else
  if docker ps -a | grep -qsw "$APPNAME"; then
    __sudo docker stop "$APPNAME" &>/dev/null
    __sudo docker rm -f "$APPNAME" &>/dev/null
  fi
  __sudo docker run -d \
    --name="$APPNAME" \
    --hostname "$SERVER_HOST" \
    --restart=unless-stopped \
    --privileged \
    -e TZ="$SERVER_TIMEZONE" \
    -v "$DATADIR/data":/data/db \
    -v /var/run/libvirt/libvirt-sock:/var/run/libvirt/libvirt-sock \
    -p $SERVER_LISTEN:$SERVER_PORT:$SERVER_PORT_INT \
    -p $SERVER_LISTEN:$SERVER_PORT_OTHER:$SERVER_PORT_OTHER_INT \
    "$HUB_URL" &>/dev/null
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Install nginx proxy
if [[ ! -f "/etc/nginx/vhosts.d/$APPNAME.conf" ]] && [[ -f "$INSTDIR/nginx/proxy.conf" ]]; then
  if __port_not_in_use "$SERVER_PORT"; then
    printf_green "Copying the nginx configuration"
    __sudo_root cp -Rf "$APPDIR/nginx/proxy.conf" "/etc/nginx/vhosts.d/$APPNAME.conf"
    sed -i "s|REPLACE_APPNAME|$APPNAME|g" "/etc/nginx/vhosts.d/$APPNAME.conf" &>/dev/null
    sed -i "s|REPLACE_NGINX_HTTP|$NGINX_HTTP|g" "/etc/nginx/vhosts.d/$APPNAME.conf" &>/dev/null
    sed -i "s|REPLACE_NGINX_HTTPS|$NGINX_HTTPS|g" "/etc/nginx/vhosts.d/$APPNAME.conf" &>/dev/null
    sed -i "s|REPLACE_SERVER_PORT|$SERVER_PORT|g" "/etc/nginx/vhosts.d/$APPNAME.conf" &>/dev/null
    sed -i "s|REPLACE_SERVER_LISTEN|$SERVER_LISTEN|g" "/etc/nginx/vhosts.d/$APPNAME.conf" &>/dev/null
    systemctl status nginx | grep -q enabled &>/dev/null && __sudo_root systemctl reload nginx &>/dev/null
  fi
fi
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# run post install scripts
run_postinst() {
  dockermgr_run_post
  if ! grep -sq "$SERVER_HOST" /etc/hosts; then
    if [[ -n "$SERVER_PORT_INT" ]]; then
      if [[ $(hostname -d 2>/dev/null | grep '^') = 'local' ]]; then
        echo "$SERVER_LISTEN     $APPNAME.local" | sudo tee -a /etc/hosts &>/dev/null
      else
        echo "$SERVER_LISTEN     $APPNAME.local" | sudo tee -a /etc/hosts &>/dev/null
        echo "$SERVER_LISTEN     $SERVER_HOST" | sudo tee -a /etc/hosts &>/dev/null
      fi
    fi
  fi
}
#
execute "run_postinst" "Running post install scripts"
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# create version file
dockermgr_install_version
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# run exit function
if docker ps -a | grep -qs "$APPNAME"; then
  printf_blue "DATADIR in $DATADIR"
  printf_cyan "Installed to $INSTDIR"
  docker exec -ti $APPNAME /webvirtmgr/manage.py createsuperuser --email=admin@$APPNAME.local
  [[ -n "$SERVER_PORT" ]] && printf_blue "Service is running on: $SERVER_IP:$SERVER_PORT"
  [[ -n "$SERVER_PORT" ]] && printf_blue "and should be available at: $SERVER_LISTEN:$SERVER_PORT or $SERVER_HOST:$SERVER_PORT"
  [[ -z "$SERVER_PORT" ]] && printf_yellow "This container does not have a web interface"
else
  printf_error "Something seems to have gone wrong with the install"
fi
run_exit &>/dev/null
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# End application
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# lets exit with code
exit ${exitCode:-$?}
