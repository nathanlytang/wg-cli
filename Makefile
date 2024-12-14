CC = gcc
CFLAGS  = -Wall -std=gnu99

# the build target executable:
TARGET = wg-cli

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) $(TARGET).c -o $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin

# Build debian package
DEB_NAME = wg-cli
DEB_VERSION = 1.0
DEB_ARCH = $(shell dpkg-architecture -qDEB_BUILD_ARCH)
DEB_MAINTAINER = Nobody <your.email@example.com>
DEB_DESCRIPTION = A tool to automate and manage WireGuard peers

deb: $(TARGET)
	mkdir -p pkg/DEBIAN
	mkdir -p pkg/usr/local/bin
	mkdir -p pkg/etc/wg-cli
	cp template.conf pkg/etc/wg-cli/
	cp $(TARGET) pkg/usr/local/bin
	echo "Package: $(DEB_NAME)" > pkg/DEBIAN/control
	echo "Version: $(DEB_VERSION)" >> pkg/DEBIAN/control
	echo "Architecture: $(DEB_ARCH)" >> pkg/DEBIAN/control
	echo "Maintainer: $(DEB_MAINTAINER)" >> pkg/DEBIAN/control
	echo "Description: $(DEB_DESCRIPTION)" >> pkg/DEBIAN/control
	echo "Depends: qrencode, wireguard, wireguard-tools" >> pkg/DEBIAN/control  # Dependencies added
	dpkg-deb --build pkg $(DEB_NAME)_$(DEB_VERSION)_$(DEB_ARCH).deb


clean:
	$(RM) $(TARGET)