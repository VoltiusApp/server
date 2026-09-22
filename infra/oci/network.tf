# Adopted from the console as it stands. Imported, never created by this config.
resource "oci_core_vcn" "main" {
  cidr_block              = "10.0.0.0/16"
  cidr_blocks             = ["10.0.0.0/16"]
  compartment_id          = "ocid1.tenancy.oc1..aaaaaaaa33dfprecs3tmxiz3romtjrqadraiopzl3dbol5y2yii7kyvwgbya"
  display_name            = "vcn-20231117-1841"
  dns_label               = "vcn11171843"
  ipv6private_cidr_blocks = []
  is_ipv6enabled          = false
}

resource "oci_core_internet_gateway" "main" {
  compartment_id = "ocid1.tenancy.oc1..aaaaaaaa33dfprecs3tmxiz3romtjrqadraiopzl3dbol5y2yii7kyvwgbya"
  display_name   = "Internet Gateway vcn-20231117-1841"
  enabled        = true
  route_table_id = null
  vcn_id         = "ocid1.vcn.oc1.eu-paris-1.amaaaaaazdvyenaanj3xa7s4gmyjbzawugxzimqrsp24sluqscxbvcak5obq"
}

resource "oci_core_default_route_table" "main" {
  compartment_id             = "ocid1.tenancy.oc1..aaaaaaaa33dfprecs3tmxiz3romtjrqadraiopzl3dbol5y2yii7kyvwgbya"
  display_name               = "Default Route Table for vcn-20231117-1841"
  manage_default_resource_id = "ocid1.routetable.oc1.eu-paris-1.aaaaaaaabdao7dcntbh5bognsjosohfrlyciu6gjdfkswlhpl5ww3ywc2oma"
  route_rules {
    description       = ""
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = "ocid1.internetgateway.oc1.eu-paris-1.aaaaaaaahigebneam7idbm72owzo744owbcd52cg3clydlbl3n56l2zit7uq"
    route_type        = "STATIC"
  }
}

resource "oci_core_default_security_list" "main" {
  compartment_id             = "ocid1.tenancy.oc1..aaaaaaaa33dfprecs3tmxiz3romtjrqadraiopzl3dbol5y2yii7kyvwgbya"
  display_name               = "Default Security List for vcn-20231117-1841"
  manage_default_resource_id = "ocid1.securitylist.oc1.eu-paris-1.aaaaaaaah4gamsrfx6z4pptnhj4ibhk7ssxttovfviofssm5vyugo5eyg3pq"
  egress_security_rules {
    description      = ""
    destination      = "0.0.0.0/0"
    destination_type = "CIDR_BLOCK"
    protocol         = "all"
    stateless        = false
  }
  ingress_security_rules {
    description = ""
    protocol    = "1"
    source      = "10.0.0.0/16"
    source_type = "CIDR_BLOCK"
    stateless   = false
    icmp_options {
      code = -1
      type = 3
    }
  }
  ingress_security_rules {
    description = ""
    protocol    = "1"
    source      = "0.0.0.0/0"
    source_type = "CIDR_BLOCK"
    stateless   = false
    icmp_options {
      code = 4
      type = 3
    }
  }
  ingress_security_rules {
    description = ""
    protocol    = "6"
    source      = "0.0.0.0/0"
    source_type = "CIDR_BLOCK"
    stateless   = false
    tcp_options {
      max = 22
      min = 22
    }
  }
  ingress_security_rules {
    description = "TermForge"
    protocol    = "6"
    source      = "0.0.0.0/0"
    source_type = "CIDR_BLOCK"
    stateless   = false
    tcp_options {
      max = 14372
      min = 14372
    }
  }
}

resource "oci_core_subnet" "main" {
  availability_domain        = null
  cidr_block                 = "10.0.0.0/24"
  compartment_id             = "ocid1.tenancy.oc1..aaaaaaaa33dfprecs3tmxiz3romtjrqadraiopzl3dbol5y2yii7kyvwgbya"
  dhcp_options_id            = "ocid1.dhcpoptions.oc1.eu-paris-1.aaaaaaaaemmggomohq4tgohlfdgbhlofoedyb3xhmdoi3rlaesm7ep6ltbaq"
  display_name               = "subnet-20231117-1841"
  dns_label                  = "subnet11171843"
  ipv4cidr_blocks            = ["10.0.0.0/24"]
  ipv6cidr_block             = null
  ipv6cidr_blocks            = []
  prohibit_internet_ingress  = false
  prohibit_public_ip_on_vnic = false
  route_table_id             = "ocid1.routetable.oc1.eu-paris-1.aaaaaaaabdao7dcntbh5bognsjosohfrlyciu6gjdfkswlhpl5ww3ywc2oma"
  security_list_ids          = ["ocid1.securitylist.oc1.eu-paris-1.aaaaaaaah4gamsrfx6z4pptnhj4ibhk7ssxttovfviofssm5vyugo5eyg3pq"]
  vcn_id                     = "ocid1.vcn.oc1.eu-paris-1.amaaaaaazdvyenaanj3xa7s4gmyjbzawugxzimqrsp24sluqscxbvcak5obq"
}
