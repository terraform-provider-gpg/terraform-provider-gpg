terraform {
  required_providers {
    gpg = {
      source = "terraform-provider-gpg/gpg"
    }
  }
}

resource "gpg_key" "this" {
  identities = [{
    name  = "John Doe"
    email = "john.doe@example.com"
  }]
  passphrase = "topsecret"
}
