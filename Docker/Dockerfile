# Fixed Dockerfile - addresses exec format error

FROM ubuntu:22.04

LABEL maintainer="Olivier Hureau"

ENV DEBIAN_FRONTEND=noninteractive

# Install necessary packages including SSH and gosu for user switching
RUN apt update && apt install -y \
    bind9 \
    dnsutils \
    iproute2 \
    gettext-base \
    dnsviz \
    software-properties-common \
    wget \
    build-essential \
    zlib1g-dev \
    libncurses5-dev \
    libgdbm-dev \
    libnss3-dev \
    libssl-dev \
    libreadline-dev \
    libffi-dev \
    libsqlite3-dev \
    curl \
    libbz2-dev \
    nano \
    openssh-server \
    gosu \
    redis\
    postgresql-client\
 && rm -rf /var/lib/apt/lists/*

# Install Python 3.13 and requirements
COPY requirements.txt /tmp/requirements.txt

RUN curl -O https://www.python.org/ftp/python/3.13.2/Python-3.13.2.tgz && \
    tar -xf Python-3.13.2.tgz && \
    cd Python-3.13.2 && \
    ./configure --enable-optimizations && \
    make -j$(nproc) && \
    make altinstall && \
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python3.13 get-pip.py && \
    pip install -r /tmp/requirements.txt && \
    rm get-pip.py && \
    cd .. && \
    rm -rf Python-3.13.2*

# Set default python3 to Python 3.13
RUN update-alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.13 1

# Configure SSH
RUN mkdir /var/run/sshd \
 && echo 'root:root' | chpasswd \
 && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && sed -i 's/#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' /etc/ssh/sshd_config \
 && sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config \
 && sed -i 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' /etc/pam.d/sshd

# Create directories for zones and keys
RUN mkdir -p \
    /data/bind1/zones /data/bind1/keys \
    /data/bind2/zones /data/bind2/keys \
    /data/bind1/keys/randomly_generated/ \
    /data/bind2/keys/randomly_generated/ \
    /data/files

# Generate rndc keys for each instance
RUN rndc-confgen -a -c /data/bind1/rndc.key && \
    rndc-confgen -a -c /data/bind2/rndc.key

# Copy the template configuration and use envsubst to generate the final files
COPY named.conf.options.template /tmp/named.conf.options.template
COPY named.conf.template /tmp/named.conf.template
COPY named.conf.local.template /tmp/named.conf.local.template
COPY db.example.com.template /tmp/db.example.com

ENV BIND_DIR="/data/bind1"
ENV BIND_IP="129.88.71.95"
ENV BIND_RNDC_PORT=953

# Substitute variables using envsubst and move them to the correct location
RUN envsubst < /tmp/named.conf.template > /data/bind1/named.conf
RUN envsubst < /tmp/named.conf.options.template > /data/bind1/named.conf.options
RUN envsubst < /tmp/named.conf.local.template > /data/bind1/named.conf.local
RUN envsubst < /tmp/db.example.com > /data/bind1/zones/db.example.com

# Same for bind instance number 2
ENV BIND_DIR="/data/bind2"
ENV BIND_IP="129.88.71.96"
ENV BIND_RNDC_PORT=954

RUN envsubst < /tmp/named.conf.template > /data/bind2/named.conf
RUN envsubst < /tmp/named.conf.options.template > /data/bind2/named.conf.options
RUN envsubst < /tmp/db.example.com > /data/bind2/zones/db.example.com
RUN envsubst < /tmp/named.conf.local.template > /data/bind2/named.conf.local

# FIXED: Only set ownership for BIND-specific directories
RUN chown -R bind:bind /data/bind1 /data/bind2

# Add the modified sign function from dns lib.
COPY dnssec.py /usr/local/lib/python3.13/site-packages/dns/dnssec.py

# Add the DNSKEY for the root domain
COPY domain_keys/* /data/bind1/keys/

# Copy original start script
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

# Setup entrypoint file
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set entrypoint to handle user permissions
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command
CMD ["/usr/local/bin/start.sh"]