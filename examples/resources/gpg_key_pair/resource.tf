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
