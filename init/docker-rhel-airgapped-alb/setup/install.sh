#!/bin/sh

DOWNLOAD_DIR="./downloads"

# Install all the local rpms
#yum -y localinstall $DOWNLOAD_DIR/*.rpm
dnf -y localinstall $DOWNLOAD_DIR/dnf/*.rpm

# Enable docker
#systemctl enable --now docker.service

# Enable Podman
systemctl enable --now podman.socket

# Load TFE image into Docker
#docker image ls
#docker load < *.tar

podman image ls
podman load < tfe.tar
