provider "oci" {
  tenancy_ocid     = var.oci_tenancy_ocid
  user_ocid        = var.oci_user_ocid
  fingerprint      = var.oci_fingerprint
  region           = var.oci_region
  private_key_path = var.oci_private_key_path
}
