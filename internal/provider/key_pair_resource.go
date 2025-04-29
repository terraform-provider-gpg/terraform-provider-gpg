package provider

import (
	"context"
	"crypto"
	"encoding/hex"
	"fmt"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	gpgcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"unsafe"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &KeyPairResource{}
var _ resource.ResourceWithValidateConfig = &KeyPairResource{}
var _ resource.ResourceWithMoveState = &KeyPairResource{}
var _ resource.ResourceWithUpgradeState = &KeyPairResource{}

func NewKeyPairResource() resource.Resource {
	return &KeyPairResource{}
}

type KeyPairResource struct {
}

const profileV4RSA = "v4_rsa"
const profileV4Curve25519 = "v4_curve25519"

func (g KeyPairResource) MoveState(ctx context.Context) []resource.StateMover {
	return []resource.StateMover{
		{
			SourceSchema: keySchema(),
			StateMover:   g.moveStateResourceKey,
		},
	}
}

// moveStateResourceKey transforms the state of an `gpg_key` resource to this resource's schema.
func (g KeyPairResource) moveStateResourceKey(ctx context.Context, req resource.MoveStateRequest, resp *resource.MoveStateResponse) {
	if req.SourceTypeName != "gpg_key" {
		return
	}
	var model keyPairModelV1
	resp.Diagnostics.Append(req.SourceState.Get(ctx, &model)...)

	if resp.Diagnostics.HasError() {
		return
	}

	model.Profile = types.StringValue(profileV4Curve25519)

	resp.Diagnostics.Append(resp.TargetState.Set(ctx, &model)...)
}

func (g KeyPairResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key_pair"
}

func (g KeyPairResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version: 1,
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "A resource for generating RSA and ECC (Curve25519) GPG keys (compatible with OpenPGP v4 / RFC4880)",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ID of the key pair in hex format.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"profile": schema.StringAttribute{
				Description: "The PGP key profile to use. Valid options are `" + profileV4RSA + "` (RSA 4096 & SHA256) or `" + profileV4Curve25519 + "` (EdDSA & Curve25519 & SHA512, default).",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(profileV4Curve25519),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Validators: []validator.String{
					stringvalidator.OneOf(profileV4Curve25519, profileV4RSA),
				},
			},
			"identities": schema.ListNestedAttribute{
				Description: "List of identities for the GPG key pair. Due to limitations in the underlying library only one identity is supported at the moment.",
				Required:    true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Description: "Name",
							Required:    true,
						},
						"email": schema.StringAttribute{
							Description: "Email",
							Required:    true,
						},
					},
				},
			},
			"passphrase": schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "Passphrase for locking the private key.",
			},
			"fingerprint": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Fingerprint of the public key.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"private_key": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Private key in armored format.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"private_key_hex": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Private key in hex format.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"public_key": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Public key in armored format.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"public_key_hex": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Public key in hex format.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (g KeyPairResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data keyPairModelV1

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if len(data.Identities) == 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("identities"),
			"GPG v4 key pairs need at least one identity",
			"GPG v4 key pairs need at least one identity.",
		)
		return
	}
}

func (g KeyPairResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data keyPairModelV1

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	var profile *profile.Custom

	switch data.Profile.ValueString() {
	case profileV4Curve25519:
		profile = RFC4880_Curve25519()
	case profileV4RSA:
		profile = RFC4880_RSA()
	default:
		resp.Diagnostics.AddError("GPG key pair generation failed", fmt.Sprintf("Unsupported profile %s", data.Profile.String()))
		return
	}
	var pgp = gpgcrypto.PGPWithProfile(profile)

	builder := pgp.KeyGeneration()
	for _, identity := range data.Identities {
		builder = builder.AddUserId(identity.Name.ValueString(), identity.Email.ValueString())
	}

	key, err := builder.New().GenerateKeyWithSecurity(constants.HighSecurity)

	if err != nil {
		resp.Diagnostics.AddError("GPG key pair generation failed", fmt.Sprintf("GenerateKeyWithSecurity failed with error: %s", err))
		return
	}
	defer key.ClearPrivateParams()

	key, err = pgp.LockKey(key, unsafe.Slice(unsafe.StringData(data.Passphrase.ValueString()), len(data.Passphrase.ValueString())))
	if err != nil {
		resp.Diagnostics.AddError("GPG key pair generation failed", fmt.Sprintf("LockKey failed with error: %s", err))
		return
	}

	privateKey, err := key.Armor()
	if err != nil {
		resp.Diagnostics.AddError("GPG key pair generation failed", fmt.Sprintf("Armor failed with error: %s", err))
		return
	}

	privateKeyHex, err := key.Serialize()
	if err != nil {
		resp.Diagnostics.AddError("GPG key pair generation failed", fmt.Sprintf("Serialize failed with error: %s", err))
		return
	}

	publicKey, err := key.GetArmoredPublicKey()
	if err != nil {
		resp.Diagnostics.AddError("GPG key generation failed", fmt.Sprintf("GetArmoredPublicKey failed with error: %s", err))
		return
	}

	publicKeyHex, err := key.GetPublicKey()
	if err != nil {
		resp.Diagnostics.AddError("GPG key pair generation failed", fmt.Sprintf("GetPublicKey failed with error: %s", err))
		return
	}

	data.Id = types.StringValue(key.GetHexKeyID())
	data.Fingerprint = types.StringValue(key.GetFingerprint())
	data.PrivateKey = types.StringValue(privateKey)
	data.PrivateKeyHex = types.StringValue(hex.EncodeToString(privateKeyHex))
	data.PublicKey = types.StringValue(publicKey)
	data.PublicKeyHex = types.StringValue(hex.EncodeToString(publicKeyHex))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (g KeyPairResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Nothing to do here.
}

// Update ensures the plan value is copied to the state to complete the update.
func (g KeyPairResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model keyPairModelV1

	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)

	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (g KeyPairResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Nothing to do here.
}

func (g KeyPairResource) UpgradeState(ctx context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{
		0: {
			PriorSchema: keySchema(),
			StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
				var priorStateData keyPairModelV0

				resp.Diagnostics.Append(req.State.Get(ctx, &priorStateData)...)
				if resp.Diagnostics.HasError() {
					return
				}

				upgradedStateData := keyPairModelV1{
					Id:            priorStateData.Id,
					Profile:       types.StringValue(profileV4Curve25519),
					Identities:    priorStateData.Identities,
					Passphrase:    priorStateData.Passphrase,
					Fingerprint:   priorStateData.Fingerprint,
					PrivateKey:    priorStateData.PrivateKey,
					PrivateKeyHex: priorStateData.PrivateKeyHex,
					PublicKey:     priorStateData.PublicKey,
					PublicKeyHex:  priorStateData.PublicKeyHex,
				}

				resp.Diagnostics.Append(resp.State.Set(ctx, upgradedStateData)...)
			},
		},
	}
}

type keyPairModelV0 struct {
	Id            types.String      `tfsdk:"id"`
	Identities    []identityModelV0 `tfsdk:"identities"`
	Passphrase    types.String      `tfsdk:"passphrase"`
	Fingerprint   types.String      `tfsdk:"fingerprint"`
	PrivateKey    types.String      `tfsdk:"private_key"`
	PrivateKeyHex types.String      `tfsdk:"private_key_hex"`
	PublicKey     types.String      `tfsdk:"public_key"`
	PublicKeyHex  types.String      `tfsdk:"public_key_hex"`
}
type keyPairModelV1 struct {
	Id            types.String      `tfsdk:"id"`
	Profile       types.String      `tfsdk:"profile"`
	Identities    []identityModelV0 `tfsdk:"identities"`
	Passphrase    types.String      `tfsdk:"passphrase"`
	Fingerprint   types.String      `tfsdk:"fingerprint"`
	PrivateKey    types.String      `tfsdk:"private_key"`
	PrivateKeyHex types.String      `tfsdk:"private_key_hex"`
	PublicKey     types.String      `tfsdk:"public_key"`
	PublicKeyHex  types.String      `tfsdk:"public_key_hex"`
}

type identityModelV0 struct {
	Name  types.String `tfsdk:"name"`
	Email types.String `tfsdk:"email"`
}

// RFC4880_Curve25519 returns a custom profile that conforms with modern algorithms available in GnuPG >=2.1 and OpenPGP v4.
func RFC4880_Curve25519() *profile.Custom {
	setKeyAlgorithm := func(cfg *packet.Config, securityLevel int8) {
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
		cfg.Curve = packet.Curve25519
		cfg.DefaultHash = crypto.SHA512
	}
	return &profile.Custom{
		SetKeyAlgorithm:      setKeyAlgorithm,
		Hash:                 crypto.SHA512,
		CipherEncryption:     packet.CipherAES256,
		CipherKeyEncryption:  packet.CipherAES256,
		CompressionAlgorithm: packet.CompressionZLIB,
	}
}

// RFC4880_RSA returns a custom profile for this library that conforms with the algorithms in RFC4880 and OpenPGP v4.
// The curves and ciphers here also ensure compatibility with BouncyCastle, as it has issues with non-AEAD Curve25519 v4 Keys.
func RFC4880_RSA() *profile.Custom {
	setKeyAlgorithm := func(cfg *packet.Config, securityLevel int8) {
		cfg.Algorithm = packet.PubKeyAlgoRSA
		cfg.RSABits = 4096
	}
	return &profile.Custom{
		SetKeyAlgorithm:      setKeyAlgorithm,
		Hash:                 crypto.SHA256,
		CipherEncryption:     packet.CipherAES256,
		CompressionAlgorithm: packet.CompressionZLIB,
	}
}
