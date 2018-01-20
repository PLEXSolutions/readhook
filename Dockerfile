FROM alpine:3.6
  
RUN apk update
RUN apk add bash curl gcc git libc-dev
#RUN apk add gdb make nasm python

WORKDIR /root
#RUN git clone https://github.com/longld/peda.git
#RUN echo "source /root/peda/peda.py" >> /root/.gdbinit
#RUN echo 'peda.execute("set breakpoint pending on")' >> /root/peda/peda.py

COPY $PWD/readhook.c /root/readhook.c
RUN gcc -fPIC -shared -o readhook.so readhook.c -ldl
RUN gcc -DREADHOOK_MAIN=1 -g -fPIC -o readhook readhook.c
