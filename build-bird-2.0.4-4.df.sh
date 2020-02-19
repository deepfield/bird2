#!/bin/bash
#
# deepfield provided shell script to build a bird debian
#

# build control variables for this script
#
# SRC of build, if local we will copy current directory
BUILD_SRC=git
BUILD_CHECK_DEP=YES
# argument handling 
# ./build-bird2-2.0.4-4-df.sh local   - will build local
# ./build-bird2-2.0.4-4-df.sh tag 2.0.4-3 - will build 2.0.4-3 tag

while (( "$#" )); do
        case "$1" in
                -h|--help) 
                 cat << USAGE
$0 [local] [tag abc] [-n|--no-depend-check]

   -n
   --no-depend-check    skip checking build dependencies
   local                will copy current directory and all subdirs into builddir
   tag <abc>            will checkout tag <abc> and build
USAGE
                 shift
                 exit 0
                 ;;
                -n|--no-depend-check)
                 BUILD_CHECK_DEP=NO
                 shift
                 ;;
                local)
                 BUILD_SRC=local
                 shift
                 ;;
                tag)
                 GIT_TAG=$2
                 shift
                 shift
                 ;;
        esac
done
#
# build - prerequisites are documented in debian/control under build-depends
#
# build dependencies
BUILD_DEPENDENCIES="build-essential autoconf flex bison libtool libncurses5-dev git libreadline-dev debhelper"

if [[ "${BUILD_CHECK_DEP}" == "YES" ]]
then
        for dep in ${BUILD_DEPENDENCIES}; do
                [[ ! $(apt-cache policy ${dep}) ]] && apt-get -y install ${dep}
        done
fi
#

PKG_NAME=bird2
PKG_VERSION=2.0.4
PKG_REV=4.df
PKG_ARCH=amd64

VERSION=${PKG_VERSION}-${PKG_REV}

GIT_REPO=https://github.com/deepfield/bird2.git
GIT_BRANCH="${GIT_TAG:-2.0.4}"

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

if [[ "$BUILD_SRC" == "git" ]]
then
        git clone -b ${GIT_BRANCH} ${GIT_REPO} ${BUILD_DIR}
        cd ${BUILD_DIR}
        git clean -dxf
fi
if [[ "$BUILD_SRC" == "local" ]]
then
        # DEV only
        mkdir -p ${BUILD_DIR}
        cd ${BUILD_DIR}
        cp -r ${CUR_DIR}/* .
fi

# build the actual debian
# generate the system dependent auto conf modules
autoreconf
# generate the configure modules
autoconf
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
