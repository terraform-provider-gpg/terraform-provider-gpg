package provider

import (
	"fmt"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"testing"
	"unsafe"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccKeyPairResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccKeyPairResourceConfig("John Doe", "john.doe@example.com", "top secret"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckGpgKeyPair("gpg_key_pair.test", packet.PubKeyAlgoEdDSA),
				),
			},
			// Update and Read testing
			{
				Config: testAccKeyPairResourceConfig("Jane Doe", "jane.doe@example.com", "top secret"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckGpgKeyPair("gpg_key_pair.test", packet.PubKeyAlgoEdDSA),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestAccKeyPairResourceWithV4RSAProfile(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccKeyPairResourceConfigWithProfile("John Doe", "john.doe@example.com", "top secret", profileV4RSA),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckGpgKeyPair("gpg_key_pair.test", packet.PubKeyAlgoRSA),
				),
			},
			// Update and Read testing
			{
				Config: testAccKeyPairResourceConfigWithProfile("Jane Doe", "jane.doe@example.com", "top secret", profileV4RSA),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckGpgKeyPair("gpg_key_pair.test", packet.PubKeyAlgoRSA),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccCheckGpgKeyPair(name string, expectedPubKeyAlgo packet.PublicKeyAlgorithm) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("could not find resource at path %s", name)
		}

		privateKey, err := crypto.NewKeyFromArmored(rs.Primary.Attributes["private_key"])
		if err != nil {
			return err
		}

		if !privateKey.IsPrivate() {
			return fmt.Errorf("expected key to be private")
		}

		locked, err := privateKey.IsLocked()
		if err != nil {
			return err
		}
		if !locked {
			return fmt.Errorf("expected key to be locked")
		}

		passphrase := rs.Primary.Attributes["passphrase"]
		privateKey, err = privateKey.Unlock(unsafe.Slice(unsafe.StringData(passphrase), len(passphrase)))
		if err != nil {
			return err
		}

		locked, err = privateKey.IsLocked()
		if err != nil {
			return err
		}
		if locked {
			return fmt.Errorf("expected key to be unlocked")
		}

		version := privateKey.GetEntity().PrivateKey.Version
		if version != 4 {
			return fmt.Errorf("unexpected key version %d", version)
		}
		algorithm := privateKey.GetEntity().PrivateKey.PublicKey.PubKeyAlgo
		if algorithm != expectedPubKeyAlgo {
			return fmt.Errorf("unexpected key algorithm %d", algorithm)
		}
		return nil
	}
}

func TestAccKeyPairResourceUpgradeStateV1(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() { testAccPreCheck(t) },
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				ExternalProviders: map[string]resource.ExternalProvider{
					"gpg": {
						Source:            "terraform-provider-gpg/gpg",
						VersionConstraint: "0.2.0",
					},
				},
				Config: testAccKeyPairResourceConfig("John Doe", "john.doe@example.com", "top secret"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckGpgKeyPair("gpg_key_pair.test", packet.PubKeyAlgoEdDSA),
				),
			},
			// Read testing
			{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Config:                   testAccKeyPairResourceConfig("John Doe", "john.doe@example.com", "top secret"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckGpgKeyPair("gpg_key_pair.test", packet.PubKeyAlgoEdDSA),
				),
			},
		},
	})
}

func testAccKeyPairResourceConfig(name string, email string, passphrase string) string {
	return fmt.Sprintf(`
resource "gpg_key_pair" "test" {
  identities = [{
	name  = %[1]q
	email = %[2]q
  }]
  passphrase = %[3]q
}
`, name, email, passphrase)
}

func testAccKeyPairResourceConfigWithProfile(name string, email string, passphrase string, profile string) string {
	return fmt.Sprintf(`
resource "gpg_key_pair" "test" {
  identities = [{
	name  = %[1]q
	email = %[2]q
  }]
  passphrase = %[3]q
  profile = %[4]q
}
`, name, email, passphrase, profile)
}
