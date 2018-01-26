# readhook
Red-team tool to hook libc read syscall with a buffer overflow vulnerability.

## Building
The file `readhook.c` is intended to be included in something else, like a Dockerfile, by cloning it and building it for the particular environment. Use the following command line in the context of the OS in which you would like to hook the read syscall:
```
./build.sh
```
## Testing
```
./test.sh
```
## Tutorial
See https://blog.polyverse.io/an-intentional-buffer-overflow-hmm-5c357238b687
