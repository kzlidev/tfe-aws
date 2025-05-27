#!/bin/sh

OS_DISTRO="$1"
OS_MAJOR_VERSION=$(grep "^VERSION_ID=" /etc/os-release | cut -d"\"" -f2 | cut -d"." -f1)
DOCKER_VERSION="24.0.9-1.el$OS_MAJOR_VERSION"

# Setup Downloads directory
DOWNLOAD_DIR="./downloads"
mkdir $DOWNLOAD_DIR
chmod -R 755 $DOWNLOAD_DIR

# Download dependencies
yum install -y --downloadonly --downloaddir=$DOWNLOAD_DIR unzip

# Download Docker
#if command -v docker > /dev/null; then
#    log "INFO" "Detected 'docker' is already installed. Skipping."
#else
#  echo "Download docker version: $DOCKER_VERSION"
#  yum install -y yum-utils
#  yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
#  yum install -y --downloadonly --downloaddir=$DOWNLOAD_DIR docker-ce-3:$DOCKER_VERSION docker-ce-cli-1:$DOCKER_VERSION containerd.io docker-compose-plugin
#fi

# Download Podman
mkdir $DOWNLOAD_DIR/dnf
dnf update -y
dnf install -y container-tools podman-docker --downloadonly --downloaddir=$DOWNLOAD_DIR/dnf
# dnf module install -y container-tools --downloadonly --downloaddir=$DOWNLOAD_DIR/dnf
# dnf install -y podman-docker --downloadonly --downloaddir=$DOWNLOAD_DIR/dnf

# Download awscli
curl -sS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "$DOWNLOAD_DIR/awscliv2.zip"

# Download TFE
echo "<HASHICORP_LICENSE>" | docker login --username terraform images.releases.hashicorp.com --password-stdin
docker save -o tfe-v202501-1.tar images.releases.hashicorp.com/hashicorp/terraform-enterprise:v202501-1
aws s3 cp ./tfe-v202501-1.tar s3://rhel-tfe-airgap-binaries/podman/tfe-v202501-1.tar

docker pull ${tfe_image_repository_url}/${tfe_image_name}:${tfe_image_tag}
echo "<HASHICORP_LICENSE>" | podman login --username terraform images.releases.hashicorp.com --password-stdin
podman pull images.releases.hashicorp.com/hashicorp/terraform-enterprise:v202406-1
podman save -o tfe.tar images.releases.hashicorp.com/hashicorp/terraform-enterprise:v202406-1
