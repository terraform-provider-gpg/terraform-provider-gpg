---
page_title: "Provider: GPG"
description: |-
  The GPG provider provides a resource to generate an ECC (Curve25519) private/public key pair.
---

# GPG Provider
The GPG provider provides a resource to generate an ECC (Curve25519) private/public key pair.

Example:
```terraform
resource "gpg_key" "this" {
  identities = [{
    name  = "John Doe"
    email = "john.doe@example.com"
  }]
  version    = "v4"
  passphrase = "topsecret"
}
```
