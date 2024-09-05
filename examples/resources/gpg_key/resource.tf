resource "gpg_key" "this" {
  identities = [{
    name  = "Jon Doe"
    email = "jon.doe@example.com"
  }]
  version    = "v4"
  passphrase = "topsecret"
}
