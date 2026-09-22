variable "oci_tenancy_ocid" {
  type = string
}

variable "oci_user_ocid" {
  type = string
}

variable "oci_fingerprint" {
  type = string
}

variable "oci_region" {
  type = string
}

variable "oci_private_key_path" {
  type        = string
  description = "API signing key. Lives beside .env.tofu and travels in the secrets bundle."
}

variable "ssh_authorized_key" {
  type        = string
  description = "Public key allowed to log in. Set TF_VAR_ssh_authorized_key in .env.tofu; not in git because this repository is public."
}
