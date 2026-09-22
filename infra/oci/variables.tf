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
