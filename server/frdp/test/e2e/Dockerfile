FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        adcli \
        bash \
        build-essential \
        ca-certificates \
        cmake \
        coreutils \
        curl \
        dnsutils \
        gawk \
        grep \
        iproute2 \
        jq \
        krb5-user \
        ldap-utils \
        libcjson-dev \
        libjpeg-dev \
        libkrb5-dev \
        libnss-sss \
        libpam-modules \
        libpam-sss \
        libpam0g-dev \
        libpng-dev \
        libssl-dev \
        libx11-dev \
        libxdamage-dev \
        libxext-dev \
        libxfixes-dev \
        libxi-dev \
        libxinerama-dev \
        libxkbcommon-dev \
        libxkbfile-dev \
        libxrandr-dev \
        libxrender-dev \
        libxtst-dev \
        libxv-dev \
        netcat-openbsd \
        ninja-build \
        openssl \
        pkg-config \
        procps \
        psmisc \
        sed \
        sssd \
        sssd-ad \
        sssd-krb5 \
        sssd-ldap \
        sssd-tools \
        util-linux \
        uuid-dev \
        x11-utils \
        xauth \
        xvfb \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

RUN cmake -S /src -B /opt/freerdp-build -GNinja \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_TESTING=ON \
        -DBUILD_TESTING_INTERNAL=ON \
        -DWITH_SERVER=ON \
        -DWITH_CLIENT=ON \
        -DWITH_X11=ON \
        -DWITH_FRDPD=ON \
        -DWITH_SHADOW=OFF \
        -DWITH_PROXY=OFF \
        -DWITH_SAMPLE=OFF \
        -DWITH_MANPAGES=OFF \
        -DWITH_WAYLAND=OFF \
        -DWITH_SDL=OFF \
        -DWITH_PULSE=OFF \
        -DWITH_ALSA=OFF \
        -DWITH_CUPS=OFF \
        -DWITH_PCSC=OFF \
        -DWITH_FFMPEG=OFF \
        -DWITH_FUSE=OFF \
        -DWITH_OPENCL=OFF \
        -DCHANNEL_URBDRC=OFF \
    && cmake --build /opt/freerdp-build --target \
        frdpd \
        frdp-authd \
        frdp-sesmand \
        frdp-session-agent \
        frdpctl \
        xfreerdp \
        TestFreeRDPFrdp \
    && cmake --install /opt/freerdp-build \
    && ldconfig

COPY server/frdp/test/e2e /opt/frdp-e2e
RUN chmod 0755 /opt/frdp-e2e/scripts/*.sh \
    && mkdir -p /artifacts /etc/frdpd /run/frdp-authd /run/frdp-sesmand /var/log/sssd \
    && chmod 0700 /run/frdp-authd /run/frdp-sesmand

ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib/x86_64-linux-gnu

ENTRYPOINT ["bash", "/opt/frdp-e2e/scripts/frdpd-entrypoint.sh"]
