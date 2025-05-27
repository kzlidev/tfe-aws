#! /bin/bash
set -euo pipefail

LOGFILE="./init.log"
TFE_CONFIG_DIR="/etc/tfe"
TFE_LICENSE_PATH="$TFE_CONFIG_DIR/tfe-license.hclic"
TFE_TLS_CERTS_DIR="$TFE_CONFIG_DIR/tls"

function log {
  local level="$1"
  local message="$2"
  local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  local log_entry="$timestamp [$level] - $message"

  echo "$log_entry" | tee -a "$LOGFILE"
}

log "INFO" "Starting TFE Installation"

minikube start
helm version
helm repo add hashicorp https://helm.releases.hashicorp.com
