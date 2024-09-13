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
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"unsafe"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &KeyResource{}
var _ resource.ResourceWithValidateConfig = &KeyResource{}

func NewGpgKeyResource() resource.Resource {
	return &KeyResource{}
}

type KeyResource struct {
}

func (g KeyResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key"
}

func (g KeyResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "A resource for generating ECC (Curve25519) GPG keys",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "ID of the key in hex format.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"identities": schema.ListNestedAttribute{
				Description: "List of identities for the GPG key. Due to limitations in the underlying library only one identity is supported at the moment.",
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
				MarkdownDescription: "Passphrase for locking the key.",
			},
			"fingerprint": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Fingerprint of the key.",
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

func (g KeyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data keyModelV1

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if len(data.Identities) == 0 {
		resp.Diagnostics.AddAttributeError(
			path.Root("identities"),
			"GPG v4 keys need at least one identity",
			"GPG v4 keys need at least one identity.",
		)
		return
	}
}

func (g KeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data keyModelV1

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	var pgp = gpgcrypto.PGPWithProfile(GnuPG())

	builder := pgp.KeyGeneration()
	for _, identity := range data.Identities {
		builder = builder.AddUserId(identity.Name.ValueString(), identity.Email.ValueString())
	}

	key, err := builder.New().GenerateKeyWithSecurity(constants.HighSecurity)

	if err != nil {
		resp.Diagnostics.AddError("GPG key generation failed", fmt.Sprintf("GenerateKeyWithSecurity failed with error: %s", err))
		return
	}
	defer key.ClearPrivateParams()

	key, err = pgp.LockKey(key, unsafe.Slice(unsafe.StringData(data.Passphrase.ValueString()), len(data.Passphrase.ValueString())))
	if err != nil {
		resp.Diagnostics.AddError("GPG key generation failed", fmt.Sprintf("LockKey failed with error: %s", err))
		return
	}

	privateKey, err := key.Armor()
	if err != nil {
		resp.Diagnostics.AddError("GPG key generation failed", fmt.Sprintf("Armor failed with error: %s", err))
		return
	}

	privateKeyHex, err := key.Serialize()
	if err != nil {
		resp.Diagnostics.AddError("GPG key generation failed", fmt.Sprintf("Serialize failed with error: %s", err))
		return
	}

	publicKey, err := key.GetArmoredPublicKey()
	if err != nil {
		resp.Diagnostics.AddError("GPG key generation failed", fmt.Sprintf("GetArmoredPublicKey failed with error: %s", err))
		return
	}

	publicKeyHex, err := key.GetPublicKey()
	if err != nil {
		resp.Diagnostics.AddError("GPG key generation failed", fmt.Sprintf("GetPublicKey failed with error: %s", err))
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

func (g KeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Nothing to do here.
}

// Update ensures the plan value is copied to the state to complete the update.
func (g KeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var model keyModelV1

	resp.Diagnostics.Append(req.Plan.Get(ctx, &model)...)

	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (g KeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Nothing to do here.
}

type keyModelV1 struct {
	Id            types.String      `tfsdk:"id"`
	Identities    []identityModelV1 `tfsdk:"identities"`
	Passphrase    types.String      `tfsdk:"passphrase"`
	Fingerprint   types.String      `tfsdk:"fingerprint"`
	PrivateKey    types.String      `tfsdk:"private_key"`
	PrivateKeyHex types.String      `tfsdk:"private_key_hex"`
	PublicKey     types.String      `tfsdk:"public_key"`
	PublicKeyHex  types.String      `tfsdk:"public_key_hex"`
}
type identityModelV1 struct {
	Name  types.String `tfsdk:"name"`
	Email types.String `tfsdk:"email"`
}

// GnuPG returns a custom profile that conforms with modern algorithms available in GnuPG >=2.1.
func GnuPG() *profile.Custom {
	setKeyAlgorithm := func(cfg *packet.Config, securityLevel int8) {
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
		cfg.Curve = packet.Curve25519
		cfg.DefaultHash = crypto.SHA512
	}
	return &profile.Custom{
		Name:                 "gpg2.1",
		SetKeyAlgorithm:      setKeyAlgorithm,
		Hash:                 crypto.SHA512,
		CipherEncryption:     packet.CipherAES256,
		CipherKeyEncryption:  packet.CipherAES256,
		CompressionAlgorithm: packet.CompressionZLIB,
	}
}
