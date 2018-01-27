FROM alpine:3.7
  
RUN	apk update
RUN	apk add bash curl gcc git libc-dev
#RUN	apk add gdb make nasm python

WORKDIR	/root
#RUN	git clone https://github.com/longld/peda.git
#RUN	echo "source /root/peda/peda.py" >> /root/.gdbinit
#RUN	echo 'peda.execute("set breakpoint pending on")' >> /root/peda/peda.py

WORKDIR	/readhook
COPY	. .

RUN	mkdir ./obj
RUN	gcc -c -fPIC -o obj/addresses.o src/addresses.c
RUN	gcc -c -fPIC -o obj/base64.o src/base64.c
RUN	gcc -c -fPIC -o obj/payload.o src/payload.c
RUN	gcc -c -fPIC -o obj/strnstr.o src/strnstr.c

RUN	mkdir ./lib
RUN	ar -cvq lib/utilhook.a obj/*.o

RUN	mkdir ./dll
RUN	gcc -fPIC -shared -o dll/basehook.so src/basehook.c lib/utilhook.a -ldl
RUN	gcc -fPIC -shared -o dll/fullhook.so src/fullhook.c lib/utilhook.a -ldl

RUN	mkdir ./app
RUN	gcc -DFULLHOOK_MAIN=1 -fPIC -o app/fullhook src/fullhook.c lib/utilhook.a
