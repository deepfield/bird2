#!/bin/bash
#
# deepfield provided shell script to build a bird debian
#
# build - prerequisites are documented in debian/control under build-depends
#

PKG_NAME=bird2
PKG_VERSION=2.0.4
PKG_REV=1.df

VERSION=${PKG_VERSION}-${PKG_REV}

GIT_REPO=https://github.com/deepfield/bird2.git
GIT_BRANCH=2.0.4

CUR_DIR=${PWD}
MAINTAINER=deepfield-syseng
BUILD_ROOT_DIR=/tmp
BUILD_DIR=${PKG_NAME}-$(date +'%s')/${PKG_NAME}-${VERSION}

mkdir -p ${BUILD_ROOT_DIR}/${BUILD_DIR}
cd ${BUILD_ROOT_DIR}

git clone -b ${GIT_BRANCH} ${GIT_REPO} ${BUILD_DIR}

cd ${BUILD_DIR}

git clean -dxf

# DEV only
# cp -r ${CUR_DIR}/debian/ .

# build the actual debian
autoreconf
# these are the default options, but let's state them specifically
./configure --enable-client --enable-pthreads --enable-memcheck \
    "--with-protocols=bfd babel bgp mrt ospf perf pipe radv rip static" \
    --enable-mpls-kernel --with-iproutedir=/etc/iproute2

ls -ahl debian
dpkg-buildpackage -b -us -uc
cd ..
mv *.deb ${CUR_DIR}
echo "Debian files have been saved in ${CUR_DIR}"

# Clean up
rm -rf ${BUILD_DIR}
