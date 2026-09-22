# Inert once adopted, and the reason a lost state file is cheap: every OCID is
# here, so a destroyed state is rebuilt by one import-only apply. Do not delete.
import {
  to = oci_core_instance.oracle
  id = "ocid1.instance.oc1.eu-paris-1.anrwiljrzdvyenac5iyr5hs2mdnhgd77epgj7h5voxiihzkldqhxm24mnyka"
}

import {
  to = oci_core_vcn.main
  id = "ocid1.vcn.oc1.eu-paris-1.amaaaaaazdvyenaanj3xa7s4gmyjbzawugxzimqrsp24sluqscxbvcak5obq"
}

import {
  to = oci_core_subnet.main
  id = "ocid1.subnet.oc1.eu-paris-1.aaaaaaaac34vxnutiqm7ehnfhjqz72w2wbqfyec726zfcebukcee46ack7ca"
}

import {
  to = oci_core_internet_gateway.main
  id = "ocid1.internetgateway.oc1.eu-paris-1.aaaaaaaahigebneam7idbm72owzo744owbcd52cg3clydlbl3n56l2zit7uq"
}

import {
  to = oci_core_default_route_table.main
  id = "ocid1.routetable.oc1.eu-paris-1.aaaaaaaabdao7dcntbh5bognsjosohfrlyciu6gjdfkswlhpl5ww3ywc2oma"
}

import {
  to = oci_core_default_security_list.main
  id = "ocid1.securitylist.oc1.eu-paris-1.aaaaaaaah4gamsrfx6z4pptnhj4ibhk7ssxttovfviofssm5vyugo5eyg3pq"
}
