#!/bin/bash
#
# deepfield provided shell script to build a bird debian
#
# build - prerequisites:
#
# set up environment
# apt-get install -y build-essential autoconf flex bison libncurses5-dev git libreadline-dev \
#    debmake
#
# git clone --depth 1 -b ${GIT_BRANCH} ${GIT_REPO}
# cd $SOURCE_DIR
# VERSION=$(cat VERSION)
#

CUR_DIR=${PWD}
MAINTAINER=deepfield-syseng
BUILD_ROOT_DIR=/tmp
BUILD_DIR=bird2-$(date +'%s')
GIT_REPO=https://github.com/deepfield/bird2.git
GIT_BRANCH=2.0.4
VERSION=2.0.4-1.df

mkdir -p ${BUILD_ROOT_DIR}/${BUILD_DIR}
cd ${BUILD_ROOT_DIR}

git clone ${GIT_REPO} ${BUILD_DIR}
cd ${BUILD_DIR}

git clean -dxf

# build the actual debian
autoreconf
# these are the default options, but let's state them specifically
./configure --enable-client --enable-pthreads --enable-memcheck "--with-protocols=bfd babel bgp mrt ospf perf pipe radv rip static" \
    --enable-mpls-kernel --with-iproutedir=/etc/iproute2

dpkg-buildpackage -rfakeroot

mv *.deb /tmp

echo "Debian files have been saved in /tmp"

cd ..

# Clean up
rm -rf $(BUILD_DIR)/bird2
