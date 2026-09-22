# OCI configuration

OpenTofu describing the compute side of production: the instance, its boot volume and
the network it sits in. Adopted the same way as `infra/cloudflare` — every resource is
imported from what already exists, and the first plan must report
`N to import, 0 to add, 0 to change, 0 to destroy`.

Adding capacity is then an entry in `var.hosts`, not an afternoon in the console. The
free `VM.Standard.A1.Flex` shape cannot be resized, so a bigger machine is always a new
instance; `ansible/migrate.yml` moves production onto it.

## Where this runs

`$ROOT/voltius-tofu/infra/oci`, beside the Cloudflare config, sharing `.env.tofu`. Run
`apply` there, never in a development checkout: a second state file is a second source
of truth.

## Credentials

Console → profile → **My profile** → **API keys** → **Add API key** → generate, then
download the private key. It grants everything your OCI user can do.

- Private key: `$ROOT/voltius-tofu/oci_api_key.pem`, mode 600.
- The rest goes in `$ROOT/voltius-tofu/.env.tofu` beside the Cloudflare token, from the
  console's configuration preview:

```sh
TF_VAR_oci_tenancy_ocid=ocid1.tenancy.oc1..…
TF_VAR_oci_user_ocid=ocid1.user.oc1..…
TF_VAR_oci_fingerprint=aa:bb:…
TF_VAR_oci_region=eu-…-1
TF_VAR_oci_private_key_path=/home/ubuntu/fourretout/voltius-tofu/oci_api_key.pem
```

Both are carried by the secrets bundle, so a rebuilt host gets them back.

```sh
cd $ROOT/voltius-tofu/infra/oci
set -a && . "$ROOT/voltius-tofu/.env.tofu" && set +a
tofu init
tofu plan
```

## Do not delete imports.tf

Same rule as Cloudflare: the import blocks are inert once adopted, they hardcode every
OCID, and they are what turns a lost state file into one import-only apply instead of
rebuilding production by hand.
