---
page_title: "Provider: GPG"
description: |-
  The GPG provider provides a resource to generate a ECC (Curve25519) private/public key pair.
---

# GPG Provider
The GPG provider provides a resource to generate a ECC (Curve25519) private/public key pair.

Example:
```terraform
resource "gpg_key" "this" {
  identities = [{
    name  = "Jon Doe"
    email = "jon.doe@example.com"
  }]
  version    = "v4"
  passphrase = "topsecret"
}
```
