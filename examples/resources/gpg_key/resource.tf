resource "gpg_key" "this" {
  identities = [{
    name  = "John Doe"
    email = "john.doe@example.com"
  }]
  version    = "v4"
  passphrase = "topsecret"
}
