FROM	centos:7
RUN	yum update -y
RUN	yum install -y bash curl gcc libc6-dev nc

WORKDIR	/readhook
COPY	src src

RUN	mkdir ./obj
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -c -o obj/addresses.o src/addresses.c
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -c -o obj/base64.o src/base64.c
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -c -o obj/payload.o src/payload.c
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -c -o obj/shellcode.o src/shellcode.c
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -c -o obj/strlcpy.o src/strlcpy.c
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -c -o obj/strnstr.o src/strnstr.c

RUN	mkdir ./lib
RUN	ar -cvq lib/utilhook.a obj/*.o

RUN	mkdir ./dll
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -Fpie -pie src/basehook.c -Wl,-z,relro,-z,now -shared -lc -ldl lib/utilhook.a -o dll/basehook.so
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -Fpie -pie src/fullhook.c -Wl,-z,relro,-z,now -shared -lc -ldl lib/utilhook.a -o dll/fullhook.so
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -Fpie -pie src/noophook.c -Wl,-z,relro,-z,now -shared -lc -ldl lib/utilhook.a -o dll/noophook.so
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -Fpie -pie src/nullhook.c -Wl,-z,relro,-z,now -shared -lc -ldl lib/utilhook.a -o dll/nullhook.so

RUN	mkdir ./app
RUN	gcc -std=gnu99 -fPIC -Fpie -pie -DFULLHOOK_MAIN=1 src/fullhook.c lib/utilhook.a -Wl,-z,relro,-z,now -lc -ldl -o app/fullhook
