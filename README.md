# Welcome to dockermgr webvirtmgr installer 👋
  
## webvirtmgr README  
  
### Requires scripts to be installed

```shell
 sudo bash -c "$(curl -LSs <https://github.com/dockermgr/installer/raw/main/install.sh>)"
 dockermgr --config && dockermgr install scripts  
```

#### Automatic install/update  

```shell
dockermgr install webvirtmgr
```


#### Manual install

```shell
git clone https://github.com/dockermgr/webvirtmgr "$HOME/.local/share/CasjaysDev/dockermgr/webvirtmgr"
bash -c "$HOME/.local/share/CasjaysDev/dockermgr/webvirtmgr/install.sh"
```
  
#### Just run

mkdir -p "$HOME/.local/share/srv/docker/webvirtmgr/"

git clone <https://github.com/dockermgr/webvirtmgr> "$HOME/.local/share/CasjaysDev/dockermgr/webvirtmgr"

cp -Rf "$HOME/.local/share/srv/docker/webvirtmgr/system/*" "$HOME/.local/share/srv/docker/webvirtmgr/"

sudo docker run -d \
--name="webvirtmgr" \
--hostname "checkip" \
--restart=unless-stopped \
--privileged \
-e TZ="${TZ:-${TIMEZONE:-America/New_York}}" \
-v "$HOME/.local/share/srv/docker/webvirtmgr/data":/data:z \
-v "$HOME/.local/share/srv/docker/webvirtmgr/config":/config:z \
-p PORT:INT_PORT \
webvirtmgr/webvirtmgr 1>/dev/null


## Author  

👤 **Jason Hempstead**  
