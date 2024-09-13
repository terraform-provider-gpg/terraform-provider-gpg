# terraform-provider-gpg

The GPG provider provides a resource to generate an ECC (Curve25519) private/public key pair.

## Documentation
Official documentation on how to use this provider can be found on the
[Terraform Registry](https://registry.terraform.io/providers/terraform-provider-gpg/gpg/latest/docs).

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.21

## Building the provider

1. Clone the repository
1. Enter the repository directory
1. Build the provider using the `go install` command. This will build the provider and put the provider binary in the `$GOPATH/bin` directory.
1. Use `go generate` to ensure the documentation is regenerated with any changes.
1. Run the acceptance tests with `make testacc`.

## Creating a new release

The release process is automated via GitHub Actions, and it's defined in the Workflow
[release.yml](./.github/workflows/release.yml).

Each release is cut by pushing a [semantically versioned](https://semver.org/) tag to the default branch. Example:

1. `git tag v0.0.1`
1. `git push --tags`
