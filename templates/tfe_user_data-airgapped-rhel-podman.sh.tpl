#! /bin/bash
set -euo pipefail

LOGFILE="/var/log/tfe-cloud-init.log"
TFE_CONFIG_DIR="/etc/tfe"
TFE_LICENSE_PATH="$TFE_CONFIG_DIR/tfe-license.hclic"
TFE_TLS_CERTS_DIR="$TFE_CONFIG_DIR/tls"
TFE_LOG_FORWARDING_CONFIG_PATH="$TFE_CONFIG_DIR/fluent-bit.conf"
AWS_REGION="${aws_region}"

function log {
  local level="$1"
  local message="$2"
  local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  local log_entry="$timestamp [$level] - $message"

  echo "$log_entry" | tee -a "$LOGFILE"
}

function create_custom_agent_image {
    cd $TFE_CONFIG_DIR
    pwd
    cat > $TFE_CONFIG_DIR/Dockerfile << EOF
FROM --platform=linux/amd64 docker.io/hashicorp/tfc-agent:latest

USER root

ADD ../tls/bundle.pem /usr/local/share/ca-certificates/tfe-bundle.crt
ADD ../tls/alb.pem /usr/local/share/ca-certificates/tfe-alb.crt
RUN chmod 644 /usr/local/share/ca-certificates/tfe-bundle.crt /usr/local/share/ca-certificates/tfe-alb.crt
RUN update-ca-certificates

RUN mkdir /.tfc-agent && \
    chmod 770 /.tfc-agent

USER tfc-agent
EOF
    log "INFO" "Dockerfile created."
    log "INFO" "Building hcp-agent-custom:latest."
    podman build -t hcp-agent-custom:latest $TFE_CONFIG_DIR/. --no-cache
    log "INFO" "Build hcp-agent-custom:latest complete."
}

function detect_os_distro {
  local OS_DISTRO_NAME=$(grep "^NAME=" /etc/os-release | cut -d"\"" -f2)
  local OS_DISTRO_DETECTED

  case "$OS_DISTRO_NAME" in 
    "Ubuntu"*)
      OS_DISTRO_DETECTED="ubuntu"
      ;;
    "CentOS"*)
      OS_DISTRO_DETECTED="centos"
      ;;
    "Red Hat"*)
      OS_DISTRO_DETECTED="rhel"
      ;;
    "Amazon Linux"*)
      OS_DISTRO_DETECTED="al2023"
      ;;
    *)
      log "ERROR" "'$OS_DISTRO_NAME' is not a supported Linux OS distro for this TFE module."
      exit_script 1
  esac

  echo "$OS_DISTRO_DETECTED"
}

function install_awscli {
  local OS_DISTRO="$1"
  local OS_VERSION=$(grep "^VERSION=" /etc/os-release | cut -d"\"" -f2)
  
  if command -v aws > /dev/null; then 
    log "INFO" "Detected 'aws-cli' is already installed. Skipping."
  else
    log "INFO" "Installing 'aws-cli'."
    curl -sS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    if command -v unzip > /dev/null; then
      unzip -qq awscliv2.zip
    else
      log "WARNING" "No 'unzip' utility found. Attempting to install 'unzip'."
      yum install unzip -y
      unzip -qq awscliv2.zip
    fi
    ./aws/install > /dev/null
    rm -f ./awscliv2.zip && rm -rf ./aws
  fi
}

function install_podman {
  local OS_DISTRO="$1"
  local OS_MAJOR_VERSION="$2"

  if command -v podman > /dev/null; then
    log "INFO" "Detected 'podman' is already installed. Skipping."
  else
    log "INFO" "Downloading podman binaries from S3"
    /usr/local/bin/aws s3 cp s3://${tfe_object_storage_s3_bucket}/dnf/ $TFE_CONFIG_DIR/downloads/dnf --recursive
    dnf -y localinstall $TFE_CONFIG_DIR/downloads/dnf/*.rpm

    systemctl enable --now podman.socket
  fi
}

function retrieve_license_from_awssm {
  local SECRET_ARN="$1"
  local SECRET_REGION=$AWS_REGION
  
  if [[ -z "$SECRET_ARN" ]]; then
    log "ERROR" "Secret ARN cannot be empty. Exiting."
    exit_script 4
  elif [[ "$SECRET_ARN" == arn:aws:secretsmanager:* ]]; then
    log "INFO" "Retrieving value of secret '$SECRET_ARN' from AWS Secrets Manager."
    TFE_LICENSE=$(/usr/local/bin/aws secretsmanager get-secret-value --region $SECRET_REGION --secret-id $SECRET_ARN --query SecretString --output text)
    echo "$TFE_LICENSE" > $TFE_LICENSE_PATH
  else
    log "WARNING" "Did not detect AWS Secrets Manager secret ARN. Setting value of secret to what was passed in."
    TFE_LICENSE="$SECRET_ARN"
    echo "$TFE_LICENSE" > $TFE_LICENSE_PATH
  fi
}

function retrieve_certs_from_awssm {
  local SECRET_ARN="$1"
  local DESTINATION_PATH="$2"
  local SECRET_REGION=$AWS_REGION
  local CERT_DATA

  if [[ -z "$SECRET_ARN" ]]; then
    log "ERROR" "Secret ARN cannot be empty. Exiting."
    exit_script 5
  elif [[ "$SECRET_ARN" == arn:aws:secretsmanager:* ]]; then
    log "INFO" "Retrieving value of secret '$SECRET_ARN' from AWS Secrets Manager."
    CERT_DATA=$(/usr/local/bin/aws secretsmanager get-secret-value --region $SECRET_REGION --secret-id $SECRET_ARN --query SecretString --output text)
    echo "$CERT_DATA" | base64 -d > $DESTINATION_PATH
  else
    log "WARNING" "Did not detect AWS Secrets Manager secret ARN. Setting value of secret to what was passed in."
    CERT_DATA="$SECRET_ARN"
    echo "$CERT_DATA" | base64 -d > $DESTINATION_PATH
  fi
}

function configure_log_forwarding {
  cat > "$TFE_LOG_FORWARDING_CONFIG_PATH" << EOF
${fluent_bit_rendered_config}
EOF
}

function generate_tfe_podman_manifest {
  local TFE_SETTINGS_PATH="$1"
  cat > $TFE_SETTINGS_PATH << EOF
---
apiVersion: "v1"
kind: "Pod"
metadata:
  labels:
    app: "tfe"
  name: "tfe"
spec:
%{ if tfe_hairpin_addressing ~}
  hostAliases:
    - ip: $VM_PRIVATE_IP
      hostnames:
        - "${tfe_hostname}"
%{ endif ~}
  containers:
  - env:
    # Application settings
    - name: "TFE_HOSTNAME"
      value: ${tfe_hostname}
    - name: "TFE_LICENSE"
      value: $TFE_LICENSE
    - name: "TFE_LICENSE_PATH"
      value: ""
    - name: "TFE_OPERATIONAL_MODE"
      value: ${tfe_operational_mode}
    - name: "TFE_ENCRYPTION_PASSWORD"
      value: $TFE_ENCRYPTION_PASSWORD
    - name: "TFE_CAPACITY_CONCURRENCY"
      value: ${tfe_capacity_concurrency}
    - name: "TFE_CAPACITY_CPU"
      value: ${tfe_capacity_cpu}
    - name: "TFE_CAPACITY_MEMORY"
      value: ${tfe_capacity_memory}
    - name: "TFE_LICENSE_REPORTING_OPT_OUT"
      value: ${tfe_license_reporting_opt_out}
    - name: "TFE_RUN_PIPELINE_DRIVER"
      value: ${tfe_run_pipeline_driver}
    - name: "TFE_RUN_PIPELINE_IMAGE"
      value: ${tfe_run_pipeline_image}
    - name: "TFE_BACKUP_RESTORE_TOKEN"
      value: ${tfe_backup_restore_token}
    - name: "TFE_NODE_ID"
      value: ${tfe_node_id}
    - name: "TFE_HTTP_PORT"
      value: 8080
    - name: "TFE_HTTPS_PORT"
      value: 8443

    # Database settings
    - name: "TFE_DATABASE_HOST"
      value: ${tfe_database_host}
    - name: "TFE_DATABASE_NAME"
      value: ${tfe_database_name}
    - name: "TFE_DATABASE_PARAMETERS"
      value: ${tfe_database_parameters}
    - name: "TFE_DATABASE_PASSWORD"
      value: ${tfe_database_password}
    - name: "TFE_DATABASE_USER"
      value: ${tfe_database_user}

    # Object storage settings
    - name: "TFE_OBJECT_STORAGE_TYPE"
      value: ${tfe_object_storage_type}
    - name: "TFE_OBJECT_STORAGE_S3_BUCKET"
      value: ${tfe_object_storage_s3_bucket}
    - name: "TFE_OBJECT_STORAGE_S3_REGION"
      value: ${tfe_object_storage_s3_region}
    - name: "TFE_OBJECT_STORAGE_S3_ENDPOINT"
      value: ${tfe_object_storage_s3_endpoint}
    - name: "TFE_OBJECT_STORAGE_S3_USE_INSTANCE_PROFILE"
      value: ${tfe_object_storage_s3_use_instance_profile}
%{ if !tfe_object_storage_s3_use_instance_profile ~}
    - name: "TFE_OBJECT_STORAGE_S3_ACCESS_KEY_ID"
      value: ${tfe_object_storage_s3_access_key_id}
    - name: "TFE_OBJECT_STORAGE_S3_SECRET_ACCESS_KEY"
      value: ${tfe_object_storage_s3_secret_access_key}
%{ endif ~}
    - name: "TFE_OBJECT_STORAGE_S3_SERVER_SIDE_ENCRYPTION"
      value: ${tfe_object_storage_s3_server_side_encryption}
    - name: "TFE_OBJECT_STORAGE_S3_SERVER_SIDE_ENCRYPTION_KMS_KEY_ID"
      value: ${tfe_object_storage_s3_server_side_encryption_kms_key_id}

%{ if tfe_operational_mode == "active-active" ~}
    # Redis settings
    - name: "TFE_REDIS_HOST"
      value: ${tfe_redis_host}
    - name: "TFE_REDIS_PASSWORD"
      value: ${tfe_redis_password}
    - name: "TFE_REDIS_USE_AUTH"
      value: ${tfe_redis_use_auth}
    - name: "TFE_REDIS_USE_TLS"
      value: ${tfe_redis_use_tls}

    # Vault cluster settings
    - name: "TFE_VAULT_CLUSTER_ADDRESS"
      value: https://$VM_PRIVATE_IP:8201
%{ endif ~}

    # TLS settings
    - name: "TFE_TLS_CERT_FILE"
      value: ${tfe_tls_cert_file}
    - name: "TFE_TLS_KEY_FILE"
      value: ${tfe_tls_key_file}
    - name: "TFE_TLS_CA_BUNDLE_FILE"
      value: ${tfe_tls_ca_bundle_file}
    - name: "TFE_TLS_CIPHERS"
      value: ${tfe_tls_ciphers}
    - name: "TFE_TLS_ENFORCE"
      value: ${tfe_tls_enforce}
    - name: "TFE_TLS_VERSION"
      value: ${tfe_tls_version}

    # Observability settings
    - name: "TFE_LOG_FORWARDING_ENABLED"
      value: ${tfe_log_forwarding_enabled}
    - name: "TFE_LOG_FORWARDING_CONFIG_PATH"
      value: $TFE_LOG_FORWARDING_CONFIG_PATH
    - name: "TFE_METRICS_ENABLE"
      value: ${tfe_metrics_enable}
    - name: "TFE_METRICS_HTTP_PORT"
      value: ${tfe_metrics_http_port}
    - name: "TFE_METRICS_HTTPS_PORT"
      value: ${tfe_metrics_https_port}

    # Docker driver settings
%{ if tfe_hairpin_addressing ~}
      # Prevent loopback with Layer 4 load balancer with hairpinning TFE agent traffic
    - name: "TFE_RUN_PIPELINE_DOCKER_EXTRA_HOSTS"
      value: ${tfe_hostname}:$VM_PRIVATE_IP
%{ endif ~}
    - name: "TFE_RUN_PIPELINE_DOCKER_NETWORK"
      value: ${tfe_run_pipeline_docker_network}
    - name: "TFE_DISK_CACHE_PATH"
      value: /var/cache/tfe-task-worker
    - name: "TFE_DISK_CACHE_VOLUME_NAME"
      value: terraform-enterprise-cache
    
    # Network settings
    - name: "TFE_IACT_SUBNETS"
      value: ${tfe_iact_subnets}
    - name: "TFE_IACT_TRUSTED_PROXIES"
      value: ${tfe_iact_trusted_proxies}
    - name: "TFE_IACT_TIME_LIMIT"
      value: ${tfe_iact_time_limit}

    image: ${tfe_image_repository_url}/${tfe_image_name}:${tfe_image_tag}
    name: "terraform-enterprise"
    ports:
    - containerPort: 8080
      hostPort: ${tfe_http_port}
    - containerPort: 8443
      hostPort: ${tfe_https_port}
    - containerPort: 8201
      hostPort: 8201
    securityContext:
      capabilities:
        add:
        - "CAP_IPC_LOCK"
        - "CAP_AUDIT_WRITE"
      readOnlyRootFilesystem: true
      seLinuxOptions:
        type: "spc_t"
    volumeMounts:
%{ if tfe_log_forwarding_enabled ~}
    - mountPath: "$TFE_LOG_FORWARDING_CONFIG_PATH"
      name: "fluent-bit"
%{ endif ~}
    - mountPath: "/etc/ssl/private/terraform-enterprise"
      name: "certs"
    - mountPath: "/var/log/terraform-enterprise"
      name: "log"
    - mountPath: "/run"
      name: "run"
    - mountPath: "/tmp"
      name: "tmp"
    - mountPath: "/run/docker.sock"
      name: "docker-sock"
    - mountPath: "/var/cache/tfe-task-worker/terraform"
      name: "terraform-enterprise-cache"
  restartPolicy: "Never"
  volumes:
%{ if tfe_log_forwarding_enabled ~}
  - hostpath:
      path: "$TFE_LOG_FORWARDING_CONFIG_PATH"
      type: "File"
    name: "fluent-bit"
%{ endif ~}
  - hostPath:
      path: "$TFE_TLS_CERTS_DIR"
      type: "Directory"
    name: "certs"
  - emptyDir:
      medium: "Memory"
    name: "log"
  - emptyDir:
      medium: "Memory"
    name: "run"
  - emptyDir:
      medium: "Memory"
    name: "tmp"
  - hostPath:
      path: "/var/run/docker.sock"
      type: "File"
    name: "docker-sock"
  - name: "terraform-enterprise-cache"
    persistentVolumeClaim:
      claimName: "terraform-enterprise-cache"
EOF
}

function generate_tfe_podman_quadlet {
  cat > $TFE_CONFIG_DIR/tfe.kube << EOF
[Unit]
Description=Terraform Enterprise Kubernetes deployment.

[Install]
WantedBy=default.target

[Service]
Restart=always

[Kube]
Yaml=tfe-pod.yaml
EOF
}

function pull_tfe_image {
  local TFE_CONTAINER_RUNTIME="$1"

  log "INFO" "Retrieving TFE image"
  /usr/local/bin/aws s3 cp s3://${tfe_object_storage_s3_bucket}/podman/tfe-${tfe_image_tag}.tar $TFE_CONFIG_DIR/downloads/tfe.tar
  podman image ls
  log "INFO" "Loading TFE image"
  podman load < $TFE_CONFIG_DIR/downloads/tfe.tar
  podman image ls
}

function exit_script { 
  if [[ "$1" == 0 ]]; then
    log "INFO" "tfe_user_data script finished successfully!"
  else
    log "ERROR" "tfe_user_data script finished with error code $1."
  fi
  
  exit "$1"
}

function main() {
  log "INFO" "Beginning TFE user_data script."
  log "INFO" "Determining Linux operating system distro..."
  OS_DISTRO=$(detect_os_distro)
  log "INFO" "Detected Linux OS distro is '$OS_DISTRO'."
  OS_MAJOR_VERSION=$(grep "^VERSION_ID=" /etc/os-release | cut -d"\"" -f2 | cut -d"." -f1)
  log "INFO" "Detected OS major version is '$OS_MAJOR_VERSION'."

  log "INFO" "Scraping EC2 instance metadata for private IP address..."
  EC2_TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  VM_PRIVATE_IP=$(curl -sS -H "X-aws-ec2-metadata-token: $EC2_TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
  log "INFO" "Detected EC2 instance private IP address is '$VM_PRIVATE_IP'."
  
  log "INFO" "Creating TFE directories..."
  mkdir -p $TFE_CONFIG_DIR $TFE_TLS_CERTS_DIR
  mkdir -p $TFE_CONFIG_DIR/downloads

  log "INFO" "Installing software dependencies..."
  install_awscli "$OS_DISTRO"
  install_podman "$OS_DISTRO" "$OS_MAJOR_VERSION"

  log "INFO" "Retrieving TFE license file..."
  retrieve_license_from_awssm "${tfe_license_secret_arn}"

  log "INFO" "Retrieving TFE TLS certificate..."
  retrieve_certs_from_awssm "${tfe_tls_cert_secret_arn}" "$TFE_TLS_CERTS_DIR/cert.pem"
  log "INFO" "Retrieving TFE TLS private key..."
  retrieve_certs_from_awssm "${tfe_tls_privkey_secret_arn}" "$TFE_TLS_CERTS_DIR/key.pem"
  log "INFO" "Retrieving TFE TLS CA bundle..."
  retrieve_certs_from_awssm "${tfe_tls_ca_bundle_secret_arn}" "$TFE_TLS_CERTS_DIR/bundle.pem"

  log "INFO" "Retrieving 'TFE_ENCRYPTION_PASSWORD' secret from ${tfe_encryption_password_secret_arn}..."
  TFE_ENCRYPTION_PASSWORD=$(/usr/local/bin/aws secretsmanager get-secret-value --region $AWS_REGION --secret-id "${tfe_encryption_password_secret_arn}" --query SecretString --output text)

  if [[ "${tfe_log_forwarding_enabled}" == "true" ]]; then
    log "INFO" "Generating '$TFE_LOG_FORWARDING_CONFIG_PATH' file for log forwarding."
    configure_log_forwarding
  fi
  
  TFE_SETTINGS_PATH="$TFE_CONFIG_DIR/tfe-pod.yaml"
  log "INFO" "Generating '$TFE_SETTINGS_PATH' Kubernetes pod manifest for TFE on Podman."
  generate_tfe_podman_manifest "$TFE_SETTINGS_PATH"
  log "INFO" "Preparing to download TFE container image..."
  pull_tfe_image "${container_runtime}"
  log "INFO" "Configuring systemd service using Quadlet to manage TFE Podman containers."
  generate_tfe_podman_quadlet
  cp "$TFE_SETTINGS_PATH" "/etc/containers/systemd"
  cp "$TFE_CONFIG_DIR/tfe.kube" "/etc/containers/systemd"

  log "INFO" "Creating custom agent image."
  create_custom_agent_image

  log "INFO" "Starting 'tfe' service (Podman containers)."
  systemctl daemon-reload
  systemctl start tfe.service

  log "INFO" "Sleeping for a minute while TFE initializes."
  sleep 60

  log "INFO" "Polling TFE health check endpoint until the app becomes ready..."
  while ! curl -ksfS --connect-timeout 5 https://$VM_PRIVATE_IP/_health_check; do
    sleep 5
  done

  exit_script 0
}

main "$@"
