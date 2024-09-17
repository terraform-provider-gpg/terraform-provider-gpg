---
page_title: "Provider: GPG"
description: |-
  The GPG provider provides a resource to generate an ECC (Curve25519) private/public key pair.
---

# GPG Provider
The GPG provider provides a resource to generate an ECC (Curve25519) private/public key pair.

Example:
```terraform
terraform {
  required_providers {
    gpg = {
      source = "terraform-provider-gpg/gpg"
    }
  }
}

resource "gpg_key_pair" "this" {
  identities = [{
    name  = "John Doe"
    email = "john.doe@example.com"
  }]
  passphrase = "topsecret"
}
```
