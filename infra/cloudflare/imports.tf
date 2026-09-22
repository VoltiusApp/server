import {
  to = cloudflare_dns_record.aaaa_updater
  id = "${var.zone_id}/c7109a32d508b2af660445a7cc2c8239"
}
import {
  to = cloudflare_dns_record.cname_apex
  id = "${var.zone_id}/c6bd36e37e66220ca40defc3c09d3bbe"
}
import {
  to = cloudflare_dns_record.cname_api
  id = "${var.zone_id}/95190f2932fa0ce8c353529b7425655e"
}
import {
  to = cloudflare_dns_record.cname_app
  id = "${var.zone_id}/b39a3364cbb26defa3ebd4c20043199e"
}
import {
  to = cloudflare_dns_record.cname_docs
  id = "${var.zone_id}/a24dd637570ba0b2a8f615e3ad0e4bbe"
}
import {
  to = cloudflare_dns_record.cname_repo
  id = "${var.zone_id}/40ffaac0eb2601801a2d187776428c8e"
}
import {
  to = cloudflare_dns_record.mx_apex_1
  id = "${var.zone_id}/32ecd5c17a6add538b8b25517a58c457"
}
import {
  to = cloudflare_dns_record.mx_apex_2
  id = "${var.zone_id}/3c4221693871eea19375dcf4f3f11cce"
}
import {
  to = cloudflare_dns_record.mx_apex_3
  id = "${var.zone_id}/5872f428e0c11b0abb246217eed0125c"
}
import {
  to = cloudflare_dns_record.mx_send
  id = "${var.zone_id}/16626db6ef4d28c87e693bcddb158b54"
}
import {
  to = cloudflare_dns_record.txt_apex
  id = "${var.zone_id}/9686cf5349ffc7bf76988e84ce457efe"
}
import {
  to = cloudflare_dns_record.txt_cf2024_1_domainkey
  id = "${var.zone_id}/fbaee685341d519d12dc106005a1e360"
}
import {
  to = cloudflare_dns_record.txt_gh_voltiusapp_o
  id = "${var.zone_id}/8b1cac62fe503973108f409c1338ccdb"
}
import {
  to = cloudflare_dns_record.txt_github_pages_challenge_voltiusapp
  id = "${var.zone_id}/07869eb9b21ebdbe723aede1618c91aa"
}
import {
  to = cloudflare_dns_record.txt_resend_domainkey
  id = "${var.zone_id}/52db14528886685f082e225307d7c15a"
}
import {
  to = cloudflare_dns_record.txt_send
  id = "${var.zone_id}/0cb5212685a6438cd640e63ab4318763"
}
import {
  to = cloudflare_dns_record.txt_vercel_1
  id = "${var.zone_id}/48f10d5dc5ab9eb55954e7795366b53a"
}
import {
  to = cloudflare_dns_record.txt_vercel_2
  id = "${var.zone_id}/d24412892f9276949e5efd52d36379e8"
}

import {
  to = cloudflare_r2_bucket.assets
  id = "${var.account_id}/voltius-assets/default"
}

import {
  to = cloudflare_r2_bucket.db_backups
  id = "${var.account_id}/voltius-db-backups/default"
}

import {
  to = cloudflare_r2_bucket.repo
  id = "${var.account_id}/voltius-repo/default"
}
