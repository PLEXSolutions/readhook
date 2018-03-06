#FROM	alpine:3.7
#RUN	apk update
#RUN	apk del musl-dev
#RUN	apk add bash curl gcc git libc-dev

FROM	centos:7.4.1708
RUN	yum update -y
RUN	yum install -y bash curl gcc git libc6-dev

#FROM	ubuntu:xenial-20180123
#RUN	apt-get update -y
#RUN	apt-get install -y curl gcc git libc6-dev

WORKDIR	/readhook
COPY	src src

RUN	mkdir ./obj
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -c -o obj/addresses.o src/addresses.c
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -c -o obj/base64.o src/base64.c
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -c -o obj/payload.o src/payload.c
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -c -o obj/strnstr.o src/strnstr.c

RUN	mkdir ./lib
RUN	ar -cvq lib/utilhook.a obj/*.o

RUN	mkdir ./dll
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -Fpie -pie src/basehook.c -Wl,-z,relro,-z,now -shared -lc -ldl lib/utilhook.a -o dll/basehook.so
RUN	gcc -std=gnu99 -fstack-protector-all -fPIC -Fpie -pie src/fullhook.c -Wl,-z,relro,-z,now -shared -lc -ldl lib/utilhook.a -o dll/fullhook.so

RUN	mkdir ./app
RUN	gcc -std=gnu99 -fPIC -Fpie -pie -DFULLHOOK_MAIN=1 src/fullhook.c lib/utilhook.a -Wl,-z,relro,-z,now -lc -ldl -o app/fullhook
