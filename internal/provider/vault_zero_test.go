package provider

import (
	"context"
	"errors"
	"testing"
)

// Zero forgets the token whatever its source, so that lock and stop leave no
// copy of it: the next request has to read its source again.
func TestVaultZeroForgetsAnEnvToken(t *testing.T) {
	ts := fakeVault(t)
	env := map[string]string{"VAULT_ADDR": ts.URL, "VAULT_TOKEN": vaultToken}
	v := &Vault{Getenv: func(k string) string { return env[k] }}
	if err := v.Available(context.Background()); err != nil {
		t.Fatal(err)
	}
	if v.token.Empty() {
		t.Fatal("the token was not kept between requests; the test proves nothing")
	}
	v.Zero()
	if !v.token.Empty() {
		t.Fatal("Zero left the token")
	}
	delete(env, "VAULT_TOKEN")
	orig := accountHome
	accountHome = func() string { return t.TempDir() } // no ~/.vault-token either
	t.Cleanup(func() { accountHome = orig })
	if err := v.Available(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("after Zero, Available = %v; the old token was still served", err)
	}
}
