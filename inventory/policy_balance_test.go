package inventory

import (
	"path/filepath"
	"testing"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/enttest"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
	"github.com/cloudreve/Cloudreve/v4/pkg/logging"
	"github.com/stretchr/testify/require"
)

func TestBalancedPoliciesResolveAndProtectDestinations(t *testing.T) {
	db := enttest.Open(t, "sqlite3", filepath.Join(t.TempDir(), "policies.db"))
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	client := NewStoragePolicyClient(db, cache.NewMemoStore("", logging.NewConsoleLogger(logging.LevelError)))
	first, err := client.Upsert(t.Context(), &ent.StoragePolicy{Name: "first", Type: types.PolicyTypeLocal, Settings: &types.PolicySetting{}})
	require.NoError(t, err)
	second, err := client.Upsert(t.Context(), &ent.StoragePolicy{Name: "second", Type: types.PolicyTypeLocal, Settings: &types.PolicySetting{}})
	require.NoError(t, err)
	balanced, err := client.Upsert(t.Context(), &ent.StoragePolicy{Name: "balanced", Type: types.PolicyTypeLoadBalance, Settings: &types.PolicySetting{BalancedPolicies: []int{first.ID, second.ID}}})
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		resolved, err := client.ResolveBalancedPolicy(t.Context(), balanced)
		require.NoError(t, err)
		require.Contains(t, []int{first.ID, second.ID}, resolved.ID)
		require.Equal(t, types.PolicyTypeLocal, resolved.Type)
	}
	require.Error(t, client.Delete(t.Context(), first))
	_, err = client.Upsert(t.Context(), &ent.StoragePolicy{Name: "nested", Type: types.PolicyTypeLoadBalance, Settings: &types.PolicySetting{BalancedPolicies: []int{balanced.ID}}})
	require.Error(t, err)
	first.Type = types.PolicyTypeLoadBalance
	first.Settings.BalancedPolicies = []int{second.ID}
	_, err = client.Upsert(t.Context(), first)
	require.Error(t, err)
	require.NoError(t, client.Delete(t.Context(), balanced))
	require.NoError(t, client.Delete(t.Context(), second))
}
