CONTAINER=birdBuild
GIT_BRANCH="${0:-2.0.4}"
# clear the source directory in the container
docker exec $CONTAINER bash -c 'cd /home/support && rm -rf bird2 && mkdir -p bird2'
# copy source from here to container
docker cp ../bird2 $CONTAINER:/home/support
# start the build
docker exec $CONTAINER bash -c "cd /home/support/bird2 && env GIT_BRANCH=${GIT_BRANCH} bash -xe build-bird-2.0.4-2.df.sh"
# retrieve the debian from the container
docker cp $CONTAINER:/home/support/bird2/bird2-2.0.4-2.df-amd64.deb .
