# readhook
Red-team tool to hook libc read syscall with a buffer overflow vulnerability.

## Building
Readhook is a set of two "hook" routines that can be injected into an application to create an intentional buffer overflow vulnerability. The two "hook" routines can be injected individually or as a chain using LD_PRELOAD. Both "hooks" insert themselves in front of the libc->read() system call and watch for magic strings to pass. Basehook.so contains the overflow enpoint alone, while fullhook.so adds helpful endpoints that assist in generating valid shellcode that can then be turned around and used in basehook.so for the actual overflow (fullhook.so also contains . Use the following command line in the context of the OS in which you would like to hook the read syscall:
```
./build.sh
```
## Testing
First, start a listener (in a different shell) for test.sh to phone-home to. e.g.
```
nc -l 5555
```
Then, run test.sh. e.g.
```
./test.sh localhost:5555
```
Test.sh will run fullhook as an application. The default host is docker.for.mac.localhost. The default port is 5555. The purpose of test.sh and fullhook (the application) are to generate a payload against fullhook (the application) and manually call the internal, vulnerable buffer overflow with the generated payload. If a listener is started first, and reachable by fullhook (the application) running in the container, it should phone-home with a reverse shell. If the reverse shell fails to connect to the listener, or if the payload is not correct (a program error that test.sh is intended to detect for developers), the program behavior is undefined and may include: segment violation, illegal addresss, illegal instruction, infinite looping, and so on. In that sense, there is only one "defined" behavior for fullhook (the application), and that behavior is to phone-home to the listener. Failure to phone-home to the listener will result in "undefined" behavior by the program. 

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
