FROM alpine:3.6
  
RUN apk update
RUN apk add bash curl gcc libc-dev
#RUN apk add gdb git make nasm python

WORKDIR /root
#RUN git clone https://github.com/longld/peda.git
#RUN echo "source /root/peda/peda.py" >> /root/.gdbinit
#RUN echo 'peda.execute("set breakpoint pending on")' >> /root/peda/peda.py

COPY redhook.c /root
RUN gcc -fPIC -shared -o redhook.so redhook.c -ldl

RUN echo "#!/bin/bash" > test.sh
#RUN echo "{ echo -ne \"HTTP/1.0 200 OK\r\n\r\n\"; echo testxyzzyDISCLOSE; } | LD_PRELOAD=/root/redhook.so nc -l -p 8080" >> test.sh
RUN echo "{ echo -ne \"HTTP/1.0 200 OK\r\n\r\n\"; echo testxyzzyOVERFLOW; } | LD_PRELOAD=/root/redhook.so nc -l -p 8080" >> test.sh
RUN chmod +x test.sh

ENTRYPOINT ["/root/test.sh"]
