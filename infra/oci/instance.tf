# Production today: 2 OCPU / 12 GB on the A1 free shape, boot volume 200 GB.
resource "oci_core_instance" "oracle" {
  availability_domain = "MTUk:EU-PARIS-1-AD-1"
  compartment_id      = "ocid1.tenancy.oc1..aaaaaaaa33dfprecs3tmxiz3romtjrqadraiopzl3dbol5y2yii7kyvwgbya"
  display_name        = "instance-20260331-1910"
  extended_metadata   = {}
  fault_domain        = "FAULT-DOMAIN-1"
  metadata = {
    ssh_authorized_keys = var.ssh_authorized_key
  }
  shape = "VM.Standard.A1.Flex"
  state = "RUNNING"
  agent_config {
    are_all_plugins_disabled = false
    is_management_disabled   = false
    is_monitoring_disabled   = false
    plugins_config {
      desired_state = "DISABLED"
      name          = "Vulnerability Scanning"
    }
    plugins_config {
      desired_state = "DISABLED"
      name          = "Management Agent"
    }
    plugins_config {
      desired_state = "ENABLED"
      name          = "Custom Logs Monitoring"
    }
    plugins_config {
      desired_state = "DISABLED"
      name          = "Compute RDMA GPU Monitoring"
    }
    plugins_config {
      desired_state = "ENABLED"
      name          = "Compute Instance Monitoring"
    }
    plugins_config {
      desired_state = "DISABLED"
      name          = "Compute HPC RDMA Auto-Configuration"
    }
    plugins_config {
      desired_state = "DISABLED"
      name          = "Compute HPC RDMA Authentication"
    }
    plugins_config {
      desired_state = "ENABLED"
      name          = "Cloud Guard Workload Protection"
    }
    plugins_config {
      desired_state = "DISABLED"
      name          = "Block Volume Management"
    }
    plugins_config {
      desired_state = "DISABLED"
      name          = "Bastion"
    }
  }
  availability_config {
    is_live_migration_preferred = false
    recovery_action             = "RESTORE_INSTANCE"
  }
  create_vnic_details {
    assign_ipv6ip             = false
    assign_private_dns_record = false
    assign_public_ip          = "true"
    display_name              = "instance-20260331-1910"
    hostname_label            = "instance-20260331-1910"
    nsg_ids                   = []
    private_ip                = "10.0.0.110"
    skip_source_dest_check    = false
    subnet_id                 = "ocid1.subnet.oc1.eu-paris-1.aaaaaaaac34vxnutiqm7ehnfhjqz72w2wbqfyec726zfcebukcee46ack7ca"
  }
  instance_options {
    are_legacy_imds_endpoints_disabled = false
  }
  launch_options {
    boot_volume_type                    = "PARAVIRTUALIZED"
    firmware                            = "UEFI_64"
    is_consistent_volume_naming_enabled = true
    network_type                        = "PARAVIRTUALIZED"
    remote_data_volume_type             = "PARAVIRTUALIZED"
  }
  shape_config {
    baseline_ocpu_utilization = "BASELINE_1_1"
    local_volume_size_in_gbs  = 0
    memory_in_gbs             = 12
    nvmes                     = 0
    ocpus                     = 2
    resource_management       = ""
    vcpus                     = 2
  }
  source_details {
    boot_volume_size_in_gbs         = "200"
    boot_volume_vpus_per_gb         = "10"
    is_preserve_boot_volume_enabled = false
    kms_key_id                      = ""
    source_id                       = "ocid1.image.oc1.eu-paris-1.aaaaaaaaqvj3h763fztlyw6ktdznbbgjmbcstvorvbfu733c3dp2bu6gy7ga"
    source_type                     = "image"
  }

  lifecycle {
    # Oracle writes these itself (CreatedBy carries an account address); the
    # console also reshuffles agent plugin entries.
    ignore_changes = [defined_tags, freeform_tags, agent_config, create_vnic_details[0].defined_tags]
  }
}
