package structs

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/strutil"
	vapi "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

type VaultTokenData struct {
	CreationTTL   int      `mapstructure:"creation_ttl"`
	TTL           int      `mapstructure:"ttl"`
	Renewable     bool     `mapstructure:"renewable"`
	Policies      []string `mapstructure:"policies"`
	Role          string   `mapstructure:"role"`
	NamespacePath string   `mapstructure:"namespace_path"`

	// root caches if the token has the "root" policy to avoid travesring the
	// policies list every time.
	root *bool
}

func (d VaultTokenData) Root() bool {
	if d.root != nil {
		return *d.root
	}

	root := strutil.StrListContains(d.Policies, "root")
	d.root = &root

	return root
}

type VaultTokenRoleData struct {
	Name                 string `mapstructure:"name"`
	ExplicitMaxTtl       int    `mapstructure:"explicit_max_ttl"`
	TokenExplicitMaxTtl  int    `mapstructure:"token_explicit_max_ttl"`
	Orphan               bool
	Period               int
	TokenPeriod          int `mapstructure:"token_period"`
	Renewable            bool
	DisallowedPolicies   []string `mapstructure:"disallowed_policies"`
	AllowedEntityAliases []string `mapstructure:"allowed_entity_aliases"`
	AllowedPolicies      []string `mapstructure:"allowed_policies"`
}

func (d VaultTokenRoleData) AllowsEntityAlias(alias string) bool {
	// Apply the same checks as
	// https://github.com/hashicorp/vault/blob/v1.10.0/vault/token_store.go#L2569-L2578
	lowcaseAlias := strings.ToLower(alias)
	return strutil.StrListContains(d.AllowedEntityAliases, lowcaseAlias) ||
		strutil.StrListContainsGlob(d.AllowedEntityAliases, lowcaseAlias)
}

func DecodeVaultSecretData(s *vapi.Secret, out interface{}) error {
	if s == nil {
		return fmt.Errorf("cannot decode nil Vault secret")
	}

	if err := mapstructure.WeakDecode(s.Data, &out); err != nil {
		return err
	}

	return nil
}
