package provider

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

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
					testAccCheckGpgKeyPair("gpg_key_pair.test"),
				),
			},
			// Update and Read testing
			{
				Config: testAccKeyPairResourceConfig("Jane Doe", "jane.doe@example.com", "top secret"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckGpgKeyPair("gpg_key_pair.test"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccCheckGpgKeyPair(name string) resource.TestCheckFunc {
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
		algorithm := privateKey.GetEntity().PrivateKey.PubKeyAlgo
		if algorithm != packet.PubKeyAlgoEdDSA {
			return fmt.Errorf("unexpected key algorithm %d", algorithm)
		}
		return nil
	}
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

func TestAccKeyPairResource_NoPassphrase(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "gpg_key_pair" "test_no_passphrase" {
  identities = [{
    name  = "Test User"
    email = "test@example.com"
  }]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckGpgKeyPairUnlocked("gpg_key_pair.test_no_passphrase"),
				),
			},
		},
	})
}

func testAccCheckGpgKeyPairUnlocked(name string) resource.TestCheckFunc {
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
		if locked {
			return fmt.Errorf("expected key to be unlocked (no passphrase)")
		}

		version := privateKey.GetEntity().PrivateKey.Version
		if version != 4 {
			return fmt.Errorf("unexpected key version %d", version)
		}
		algorithm := privateKey.GetEntity().PrivateKey.PubKeyAlgo
		if algorithm != packet.PubKeyAlgoEdDSA {
			return fmt.Errorf("unexpected key algorithm %d", algorithm)
		}
		return nil
	}
}
