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

RUN	gcc -c -fPIC -o obj/addresses.o src/addresses.c
RUN	gcc -c -fPIC -o obj/base64.o src/base64.c
RUN	gcc -c -fPIC -o obj/payload.o src/payload.c
RUN	gcc -c -fPIC -o obj/strnstr.o src/strnstr.c

RUN	gcc -fPIC -shared -o makeload.so src/makeload.c obj/addresses.o obj/base64.o obj/payload.o obj/strnstr.o -ldl
RUN	gcc -DMAKELOAD_MAIN=1 -fPIC -o makeload src/makeload.c obj/addresses.o obj/base64.o obj/payload.o obj/strnstr.o

RUN	gcc -fPIC -shared -o readhook.so src/readhook.c obj/addresses.o obj/base64.o obj/payload.o obj/strnstr.o -ldl
RUN	gcc -DREADHOOK_MAIN=1 -fPIC -o readhook src/readhook.c obj/addresses.o obj/base64.o obj/payload.o obj/strnstr.o
