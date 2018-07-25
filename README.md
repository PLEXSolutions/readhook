# readhook3d
Red-team tool to hook libc read syscall with a buffer overflow vulnerability.

## Building
Readhook3d consists of a set of shared libraries that can be injected into an application to create an intentional buffer overflow vulnerability. The hook routines basehook.so and fullhook.so can be injected individually or as a chain using LD_PRELOAD. Both hooks insert themselves in front of the libc->read() system call and watch for magic strings to pass. Basehook.so contains the overflow endpoint alone, while fullhook.so adds helpful endpoints that assist in generating valid shellcode that can then be turned around and used by basehook.so for the actual overflow (fullhook.so also contains an overflow endpoint for convenience). (Additionally, there are two helper hooks for developers; nullhook.so which does nothing, and noophook.so which injects itself before the libc->read() function and simply passes the request through.)
```
./build.sh
```
## Testing
Test.sh will run fullhook as an application. The purpose of test.sh and fullhook (the application) are to generate a payload against fullhook (the application) and manually call the internal, vulnerable buffer overflow with the generated payload. If the payload is correct and works, it will execute the packaged command (which presently is "tput bel", which causes a bell sound to be played. If the payload is not correct (a program error that test.sh is intended to detect for developers), the program behavior is undefined and may include: segment violation, illegal addresss, illegal instruction, infinite looping, and so on.
```
./test.sh
