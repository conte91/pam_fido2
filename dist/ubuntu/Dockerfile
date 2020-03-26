# Container with needed dependencies to build the pam-fido2 .deb package
# for Ubuntu.

FROM ubuntu:18.04
RUN \
	apt-get update && \
	apt-get -y dist-upgrade && \
	apt-get -y install build-essential cmake curl libcbor-dev libssl-dev \
			libudev-dev libpam-dev meson vim && \
	apt-get clean && \
	mkdir /meson && \
	curl -L https://github.com/mesonbuild/meson/releases/download/0.54.0.rc1/meson-0.54.0rc1.tar.gz | tar xzf -  -C /meson && \
	mkdir /app && mkdir /app/build

