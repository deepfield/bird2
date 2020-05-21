ARG BASE_IMAGE=276327358223.dkr.ecr.us-east-1.amazonaws.com/pipedream-dev
ARG TAG=latest

FROM ${BASE_IMAGE}:${TAG}

RUN bash -c "apt-get update"
# install build dependencies
RUN bash -c "apt-get -y install build-essential autoconf flex bison git libncurses5-dev libreadline-dev debhelper" 
