// Package secrets adapts Filament's encrypted secret providers to oauth.Store.
package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/galaxy-io/filament"
	"github.com/galaxy-io/filament/oauth"
)

// updater is an optional secret-provider capability. The callback runs under
// an exclusive database lock, including across processes.
type updater interface {
	UpdateSecret(context.Context, filament.TenantID, string, func(filament.Secret) (filament.Secret, error)) (filament.Secret, error)
}

// Store owns one tenant's OAuth authorization, independently of connection or
// pipeline versions. Use the same ID wherever that authorization is shared.
type Store struct {
	provider filament.Secrets
	updater  updater
	tenant   filament.TenantID
	ref      string
}

var _ oauth.Store = (*Store)(nil)

// New binds an existing secret provider. Postgres and SQLite support atomic
// updates. Other providers are rejected rather than silently losing rotations.
func New(provider filament.Secrets, tenant filament.TenantID, id string) (*Store, error) {
	if tenant == "" || id == "" || strings.ContainsAny(string(tenant)+id, "/\\") {
		return nil, errors.New("oauth: tenant and credential ID must be nonempty path segments")
	}
	u, ok := provider.(updater)
	if !ok {
		return nil, errors.New("oauth: secret provider does not support atomic token updates")
	}
	return &Store{provider: provider, updater: u, tenant: tenant, ref: fmt.Sprintf("%s%s/oauth/%s", filament.ConnectionSecretPrefix, tenant, id)}, nil
}

// Set seeds or explicitly replaces an authorization, for example from a
// manually supplied refresh token or a future authorization-code exchange.
// The provider serializes replacement against an in-flight refresh.
func (s *Store) Set(ctx context.Context, token oauth.Token) error {
	if token.AccessToken == "" && token.RefreshToken == "" {
		return errors.New("oauth: a token is required")
	}
	value, err := json.Marshal(token) // #nosec G117 -- token payload goes only to the encrypted secret provider.
	if err != nil {
		return errors.New("oauth: cannot encode token")
	}
	return s.provider.Write(ctx, s.ref, filament.Secret{Tenant: s.tenant, Value: value})
}

// Delete removes local credentials. Provider-side revocation is separate.
func (s *Store) Delete(ctx context.Context) error { return s.provider.Delete(ctx, s.ref) }

// Update runs fn under the provider's database lock and commits encrypted state.
func (s *Store) Update(ctx context.Context, fn func(context.Context, oauth.Token) (oauth.Token, error)) (oauth.Token, error) {
	// Keep database lock ownership bounded even when a caller has no deadline.
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	secret, err := s.updater.UpdateSecret(ctx, s.tenant, s.ref, func(secret filament.Secret) (filament.Secret, error) {
		var current oauth.Token
		if err := json.Unmarshal(secret.Value, &current); err != nil {
			return filament.Secret{}, errors.New("oauth: cannot decode stored token")
		}
		next, err := fn(ctx, current)
		if err != nil {
			return filament.Secret{}, err
		}
		if next == current {
			return secret, nil
		}
		value, err := json.Marshal(next) // #nosec G117 -- token payload goes only to the encrypted secret provider.
		if err != nil {
			return filament.Secret{}, errors.New("oauth: cannot encode token")
		}
		secret.Value = value
		return secret, nil
	})
	if err != nil {
		return oauth.Token{}, err
	}
	var token oauth.Token
	if err := json.Unmarshal(secret.Value, &token); err != nil {
		return oauth.Token{}, errors.New("oauth: cannot decode stored token")
	}
	return token, nil
}
