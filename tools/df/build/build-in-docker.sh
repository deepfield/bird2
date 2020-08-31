#
# this runs the build-bird script in a container  (possibly having cached all the build dependencies)
#
CONTAINER=bird-build
GIT_TAG="${1:-2.0.4-6.df}"
ARCH=amd64
# clear the source directory in the container
docker exec $CONTAINER bash -c 'cd /home/support && rm -rf bird2 && mkdir -p bird2'
# copy source from here to container
docker cp ../bird2 $CONTAINER:/home/support
# start the build
docker exec $CONTAINER bash -c "cd /home/support/bird2 && bash -xe build-bird-${GIT_TAG}.sh tag ${GIT_TAG}"
# retrieve the debian from the container
docker cp $CONTAINER:/home/support/bird2/bird2-${GIT_TAG}-${ARCH}.deb .
