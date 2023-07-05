# base image 
ARG BASE_IMAGE=ubuntu
ARG TAG=22.04
ARG BIRD_TAG=2.0.4-9.df
ARG ARCH=amd64

FROM ${BASE_IMAGE}:${TAG}

ENV BIRD_TAG=${BIRD_TAG}
ENV ARCH=${ARCH}


RUN apt-get update &&\
    apt-get install -y locales && \
    localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8

RUN locale-gen en_US.UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

# bird2-2.0.4-9.df-amd64.deb
RUN apt-get -y install build-essential autoconf flex bison libtool libncurses5-dev \
                   git libreadline-dev debhelper


COPY support-sudoers /etc/sudoers.d/support


RUN useradd -ms /bin/bash support 
ENV HOME=/home/support PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/mysql/bin:/usr/local/mysql/scripts
WORKDIR $HOME

ADD media media
RUN dpkg -i media/bird2-2.0.4-9.df-amd64.deb

USER support
