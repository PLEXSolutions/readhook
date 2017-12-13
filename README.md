# redhook
Red-team tool to hook libc read syscall with a buffer overflow vulnerability.

## Building

The file `redhook.c` is built as part of the Docker image build process, resulting in a shared library called `redhook.so` which contains a wrapper that is loaded (using LD_PRELOAD) before an application is run, introducing a buffer overflow vulnerability.
```
sh build.sh [options to pv build docker]
```

## Usage

```
TBD
```

## Testing

```
sh redhook.sh
```
