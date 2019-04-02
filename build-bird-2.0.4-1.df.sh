#!/bin/bash
#
# deepfield provided shell script to build a bird debian
#
# build - prerequisites are documented in debian/control under build-depends
#
# build dependencies
apt-get -y install build-essential autoconf flex bison libtool libncurses5-dev \
                   git libreadline-dev debhelper
#

PKG_NAME=bird2
PKG_VERSION=2.0.4
PKG_REV=1.df
PKG_ARCH=amd64

VERSION=${PKG_VERSION}-${PKG_REV}

GIT_REPO=https://github.com/deepfield/bird2.git
GIT_BRANCH=2.0.4

CUR_DIR=${PWD}
#
# directory layout
#
# /tmp/bird2-<epoch>/<BUILD_DIR> - git clone
# /tmp/bird2-<epoch>/<PACKAGE_DIR> - binaries and DEBIAN
BUILD_ROOT_DIR=/tmp
BUILD_PARENT_DIR=${BUILD_ROOT_DIR}/${PKG_NAME}-$(date +'%s')
BUILD_DIR=${PKG_NAME}-${VERSION}
PACKAGE_DIR=${PKG_NAME}-${VERSION}-${PKG_ARCH}
PACKAGE_NAME=${PKG_NAME}-${VERSION}-${PKG_ARCH}.deb

mkdir -p ${BUILD_PARENT_DIR}
cd ${BUILD_PARENT_DIR}

git clone -b ${GIT_BRANCH} ${GIT_REPO} ${BUILD_DIR}

cd ${BUILD_DIR}

git clean -dxf

# DEV only
# cp -r ${CUR_DIR}/DEBIAN/ .

# build the actual debian
autoreconf
# these are the default options, but let's state them specifically
./configure --enable-client --enable-pthreads --enable-memcheck \
    "--with-protocols=bfd babel bgp mrt ospf perf pipe radv rip static" \
    --with-iproutedir=/etc/iproute2
make
#
# build the package directory
#
make install DESTDIR=../${PACKAGE_DIR}
cd ..
# override the example bird configuration in the package with our minimal bird configuration
cp ${BUILD_DIR}/bird-minimal.conf ${PACKAGE_DIR}/usr/local/etc/bird.conf
# copy DEBIAN binary packages into the packaging directory
cp -r ${BUILD_DIR}/DEBIAN ${PACKAGE_DIR}/DEBIAN
dpkg-deb --build ${PACKAGE_DIR} ${PACKAGE_NAME}

mv *.deb ${CUR_DIR}
echo "Debian files have been saved in ${CUR_DIR}"

# Clean up
rm -rf ${BUILD_PARENT_DIR}
