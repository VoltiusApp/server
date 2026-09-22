resource "cloudflare_dns_record" "aaaa_updater" {
  zone_id = var.zone_id
  name    = "updater.voltius.app"
  type    = "AAAA"
  content = "100::"
  ttl     = 1
  proxied = true
}

resource "cloudflare_dns_record" "cname_apex" {
  zone_id = var.zone_id
  name    = "voltius.app"
  type    = "CNAME"
  content = "92ccdbd4886c97cc.vercel-dns-017.com"
  ttl     = 600
  proxied = false
}

resource "cloudflare_dns_record" "cname_api" {
  zone_id = var.zone_id
  name    = "api.voltius.app"
  type    = "CNAME"
  content = "${local.api_tunnel_id}.cfargotunnel.com"
  ttl     = 1
  proxied = true
}

resource "cloudflare_dns_record" "cname_app" {
  zone_id = var.zone_id
  name    = "app.voltius.app"
  type    = "CNAME"
  content = "4144654bdd21ff54.vercel-dns-017.com"
  ttl     = 600
  proxied = false
}

resource "cloudflare_dns_record" "cname_docs" {
  zone_id = var.zone_id
  name    = "docs.voltius.app"
  type    = "CNAME"
  content = "voltiusapp.github.io"
  ttl     = 1
  proxied = false
}

resource "cloudflare_dns_record" "cname_repo" {
  zone_id = var.zone_id
  name    = "repo.voltius.app"
  type    = "CNAME"
  content = "public.r2.dev"
  ttl     = 1
  proxied = true
}

resource "cloudflare_dns_record" "mx_apex_1" {
  zone_id  = var.zone_id
  name     = "voltius.app"
  type     = "MX"
  content  = "route1.mx.cloudflare.net"
  ttl      = 1
  priority = 83
}

resource "cloudflare_dns_record" "mx_apex_2" {
  zone_id  = var.zone_id
  name     = "voltius.app"
  type     = "MX"
  content  = "route2.mx.cloudflare.net"
  ttl      = 1
  priority = 19
}

resource "cloudflare_dns_record" "mx_apex_3" {
  zone_id  = var.zone_id
  name     = "voltius.app"
  type     = "MX"
  content  = "route3.mx.cloudflare.net"
  ttl      = 1
  priority = 2
}

resource "cloudflare_dns_record" "mx_send" {
  zone_id  = var.zone_id
  name     = "send.voltius.app"
  type     = "MX"
  content  = "feedback-smtp.eu-west-1.amazonses.com"
  ttl      = 3600
  priority = 10
}

resource "cloudflare_dns_record" "txt_apex" {
  zone_id = var.zone_id
  name    = "voltius.app"
  type    = "TXT"
  content = "\"v=spf1 include:_spf.mx.cloudflare.net ~all\""
  ttl     = 1
}

resource "cloudflare_dns_record" "txt_cf2024_1_domainkey" {
  zone_id = var.zone_id
  name    = "cf2024-1._domainkey.voltius.app"
  type    = "TXT"
  content = "\"v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiweykoi+o48IOGuP7GR3X0MOExCUDY/BCRHoWBnh3rChl7WhdyCxW3jgq1daEjPPqoi7sJvdg5hEQVsgVRQP4DcnQDVjGMbASQtrY4WmB1VebF+RPJB2ECPsEDTpeiI5ZyUAwJaVX7r6bznU67g7LvFq35yIo4sdlmtZGV+i0H4cpYH9+3JJ78k\" \"m4KXwaf9xUJCWF6nxeD+qG6Fyruw1Qlbds2r85U9dkNDVAS3gioCvELryh1TxKGiVTkg4wqHTyHfWsp7KD3WQHYJn0RyfJJu6YEmL77zonn7p2SRMvTMP3ZEXibnC9gz3nnhR6wcYL8Q7zXypKTMD58bTixDSJwIDAQAB\""
  ttl     = 1
}

resource "cloudflare_dns_record" "txt_gh_voltiusapp_o" {
  zone_id = var.zone_id
  name    = "_gh-voltiusapp-o.voltius.app"
  type    = "TXT"
  content = "\"64e404816c\""
  ttl     = 1
}

resource "cloudflare_dns_record" "txt_github_pages_challenge_voltiusapp" {
  zone_id = var.zone_id
  name    = "_github-pages-challenge-voltiusapp.voltius.app"
  type    = "TXT"
  content = "\"2d5bb325e787e72d9e57a5c7ec9fb6\""
  ttl     = 1
}

resource "cloudflare_dns_record" "txt_resend_domainkey" {
  zone_id = var.zone_id
  name    = "resend._domainkey.voltius.app"
  type    = "TXT"
  content = "\"p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDSFpcYjqlh4XrVuzDxpgLhDs/TAv0YuS6L6yMvm9oGDjTchDZPzGqKGBsruDBipRjZV+Ulo0O0n75J1VtpmuVLL6VlAco2FQhSiO04iv7g/CV4JFqM1A/3xIIgzVSnIHzlPCTsVTe4ymg2YCgIyLuxnn9SbsL9I59P7PeCzONdIQIDAQAB\""
  ttl     = 3600
}

resource "cloudflare_dns_record" "txt_send" {
  zone_id = var.zone_id
  name    = "send.voltius.app"
  type    = "TXT"
  content = "\"v=spf1 include:amazonses.com ~all\""
  ttl     = 3600
}

resource "cloudflare_dns_record" "txt_vercel_1" {
  zone_id = var.zone_id
  name    = "_vercel.voltius.app"
  type    = "TXT"
  content = "\"vc-domain-verify=app.voltius.app,62de4a401ab52da27e62,dc\""
  ttl     = 600
}

resource "cloudflare_dns_record" "txt_vercel_2" {
  zone_id = var.zone_id
  name    = "_vercel.voltius.app"
  type    = "TXT"
  content = "\"vc-domain-verify=voltius.app,945aac85ec028b7aa2cf,dc\""
  ttl     = 1
}
