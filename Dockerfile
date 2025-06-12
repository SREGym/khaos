FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    nginx \
    fcgiwrap \
    spawn-fcgi \
    gcc \
	clang \
    curl \
	llvm \
	build-essential \
	pkg-config \
	libelf-dev \
	make \
	#linux-headers-$(uname -r || uname -a | awk '{print $3}') \
	#linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

RUN ls -l /usr/include

# Copy configuration
COPY docker-config/nginx.conf /etc/nginx/nginx.conf

# TODO: confirm that the node will permit BPF calls


# Compile files and place binaries into cgi-bin folder
RUN mkdir -p /app/cgi-bin
COPY khaos.c /app/cgi-bin/khaos.c
COPY khaos.bpf.c /app/cgi-bin/khaos.bpf.c
COPY Makefile /app/cgi-bin/Makefile
COPY libbpf /app/cgi-bin/libbpf

RUN ls -l

RUN bash -xc "\
cd /app/cgi-bin; \
#pushd libbpf/src; \
#make install; \
#popd; \
make"

COPY khaos /app/cgi-bin/khaos.cgi
RUN chmod +x /app/cgi-bin/khaos.cgi

# Copy nginx config and entrypoint
COPY docker-config/nginx.conf /etc/nginx/nginx.conf
COPY docker-config/entrypoint.sh /entrypoint.sh
COPY docker-config/fastcgi_params /etc/nginx/fastcgi_params
RUN chmod +x /entrypoint.sh

# TODO: This is not an HTTP service, perhaps use a different port
EXPOSE 80

CMD ["/entrypoint.sh"]

