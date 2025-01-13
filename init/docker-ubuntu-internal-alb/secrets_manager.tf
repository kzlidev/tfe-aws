resource "aws_secretsmanager_secret" "tfe_license_secret" {
  name                    = "${var.friendly_name_prefix}-tfe-license-secret"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret" "tfe_encryption_password_secret" {
  name                    = "${var.friendly_name_prefix}-tfe-encryption-password-secret"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret" "tfe_tls_cert_secret" {
  name                    = "${var.friendly_name_prefix}-tfe-tls-cert-key"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret" "tfe_tls_privkey_secret" {
  name                    = "${var.friendly_name_prefix}-tfe-tls-privkey-key"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret" "tfe_tls_ca_bundle_secret" {
  name                    = "${var.friendly_name_prefix}-tfe-tls-ca-bundle"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret" "tfe_database_password_secret" {
  name                    = "${var.friendly_name_prefix}-tfe-database-password-secret"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "tfe_license_secret" {
  secret_id     = aws_secretsmanager_secret.tfe_license_secret.id
  secret_string = file("${path.module}/../../../terraform.hclic")
}

resource "aws_secretsmanager_secret_version" "tfe_database_password_secret" {
  secret_id     = aws_secretsmanager_secret.tfe_database_password_secret.id
  secret_string = base64encode("tfedbpassword")
}

resource "aws_secretsmanager_secret_version" "tfe_encryption_password_secret" {
  secret_id     = aws_secretsmanager_secret.tfe_encryption_password_secret.id
  secret_string = base64encode(var.tfe_encryption_password_secret)
}

resource "aws_secretsmanager_secret_version" "tfe_tls_cert_secret" {
  secret_id     = aws_secretsmanager_secret.tfe_tls_cert_secret.id
  #  secret_string = base64encode(tls_locally_signed_cert.cluster_signed_cert.cert_pem)
  secret_string = base64encode(tls_self_signed_cert.ca_cert.cert_pem)
}

resource "aws_secretsmanager_secret_version" "tfe_tls_privkey_secret" {
  secret_id     = aws_secretsmanager_secret.tfe_tls_privkey_secret.id
  #  secret_string = base64encode(tls_private_key.cluster_private_key.private_key_pem)
  secret_string = base64encode(tls_private_key.ca_private_key.private_key_pem)
}

resource "aws_secretsmanager_secret_version" "tfe_tls_ca_bundle_secret" {
  secret_id     = aws_secretsmanager_secret.tfe_tls_ca_bundle_secret.id
  secret_string = base64encode(tls_self_signed_cert.ca_cert.cert_pem)
}
