# readhook
Red-team tool to hook libc read syscall with a buffer overflow vulnerability.

## Building
Readhook is a set of two "hook" routines that can be injected into an application to create an intentional buffer overflow vulnerability. The two "hook" routines can be injected individually or as a chain using LD_PRELOAD. Both "hooks" insert themselves in front of the libc->read() system call and watch for magic strings to pass. Basehook.so contains the overflow enpoint alone, while fullhook.so adds helpful endpoints that assist in generating valid shellcode that can then be turned around and used in basehook.so for the actual overflow (fullhook.so also contains . Use the following command line in the context of the OS in which you would like to hook the read syscall:
```
./build.sh
```
## Testing
Start listenter on host:port in another shell before running the following command:
```
./test.sh <host<:port>>
```
Test.sh will run fullhook as an application. The default host is docker.for.mac.localhost. The default port is 5555. 

## Tutorial
See https://blog.polyverse.io/an-intentional-buffer-overflow-hmm-5c357238b687

## Additional Resources
This repository contains a simple node-based echo server with instructions on running under readhook.
```
git clone https://github.com/polyverse/node-echo-server
```
This repository contains the same node-based echo server built with readhook already pre-installed.
```
git clone https://github.com/polyverse/readhook-node-echo-server
```
