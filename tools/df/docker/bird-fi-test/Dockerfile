# base image 
ARG BASE_IMAGE=276327358223.dkr.ecr.us-east-1.amazonaws.com/pipedream-dev
ARG TAG=latest
ARG BIRD_TAG=2.0.4-9.df
ARG ARCH=amd64

FROM ${BASE_IMAGE}:${TAG}

ENV BIRD_TAG=${BIRD_TAG}
ENV ARCH=${ARCH}

WORKDIR /home/support
ADD media media

# bird2-2.0.4-9.df-amd64.deb
RUN bash -c "dpkg -i /home/support/media/bird2-2.0.4-9.df-amd64.deb"
RUN bash -c "/usr/local/sbin/bird -c /usr/local/etc/bird.conf"
