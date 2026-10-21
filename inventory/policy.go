package inventory

import (
	"context"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"math/big"
	"strconv"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/storagepolicy"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/cloudreve/Cloudreve/v4/pkg/cache"
)

const (
	// StoragePolicyCacheKey is the cache key of storage policy.
	StoragePolicyCacheKey = "storage_policy_"
)

func init() {
	gob.Register(ent.StoragePolicy{})
	gob.Register([]ent.StoragePolicy{})
}

type (
	LoadStoragePolicyGroup struct{}
	SkipStoragePolicyCache struct{}

	StoragePolicyClient interface {
		TxOperator
		// GetByGroup returns the storage policies of the group.
		GetByGroup(ctx context.Context, group *ent.Group) (*ent.StoragePolicy, error)
		// GetPolicyByID returns the storage policy by id.
		GetPolicyByID(ctx context.Context, id int) (*ent.StoragePolicy, error)
		ResolveBalancedPolicy(ctx context.Context, policy *ent.StoragePolicy) (*ent.StoragePolicy, error)
		// UpdateAccessKey updates the access key of the storage policy. It also clear related cache in KV.
		UpdateAccessKey(ctx context.Context, policy *ent.StoragePolicy, token string) error
		// ListPolicyByType returns the storage policies by type.
		ListPolicyByType(ctx context.Context, t types.PolicyType) ([]*ent.StoragePolicy, error)
		// ListPolicies returns the storage policies with pagination.
		ListPolicies(ctx context.Context, args *ListPolicyParameters) (*ListPolicyResult, error)
		// Upsert upserts the storage policy.
		Upsert(ctx context.Context, policy *ent.StoragePolicy) (*ent.StoragePolicy, error)
		// Delete deletes the storage policy.
		Delete(ctx context.Context, policy *ent.StoragePolicy) error
	}

	ListPolicyParameters struct {
		*PaginationArgs
		Type types.PolicyType
	}

	ListPolicyResult struct {
		*PaginationResults
		Policies []*ent.StoragePolicy
	}
)

// NewStoragePolicyClient returns a new StoragePolicyClient.
func NewStoragePolicyClient(client *ent.Client, cache cache.Driver) StoragePolicyClient {
	return &storagePolicyClient{client: client, cache: cache}
}

type storagePolicyClient struct {
	client *ent.Client
	cache  cache.Driver
}

// ResolveBalancedPolicy picks a physical destination once per upload. The resolved
// policy is persisted on the entity, so subsequent reads never rebalance a file.
func (c *storagePolicyClient) ResolveBalancedPolicy(ctx context.Context, policy *ent.StoragePolicy) (*ent.StoragePolicy, error) {
	if policy.Type != types.PolicyTypeLoadBalance {
		return policy, nil
	}
	if policy.Settings == nil || len(policy.Settings.BalancedPolicies) == 0 {
		return nil, fmt.Errorf("load balancing policy has no destinations")
	}
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(policy.Settings.BalancedPolicies))))
	if err != nil {
		return nil, err
	}
	resolved, err := c.GetPolicyByID(ctx, policy.Settings.BalancedPolicies[index.Int64()])
	if err != nil {
		return nil, err
	}
	if resolved.Type == types.PolicyTypeLoadBalance {
		return nil, fmt.Errorf("nested load balancing policies are not supported")
	}
	return resolved, nil
}

func (c *storagePolicyClient) SetClient(newClient *ent.Client) TxOperator {
	return &storagePolicyClient{client: newClient, cache: c.cache}
}

func (c *storagePolicyClient) GetClient() *ent.Client {
	return c.client
}

func (c *storagePolicyClient) Delete(ctx context.Context, policy *ent.StoragePolicy) error {
	balanced, err := c.ListPolicyByType(ctx, types.PolicyTypeLoadBalance)
	if err != nil {
		return err
	}
	for _, parent := range balanced {
		if parent.Settings == nil {
			continue
		}
		for _, id := range parent.Settings.BalancedPolicies {
			if id == policy.ID {
				return fmt.Errorf("storage policy is referenced by load balancing policy %d", parent.ID)
			}
		}
	}
	if err := c.client.StoragePolicy.DeleteOne(policy).Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete storage policy: %w", err)
	}

	// Clear cache
	if err := c.cache.Delete(StoragePolicyCacheKey, strconv.Itoa(policy.ID)); err != nil {
		return fmt.Errorf("failed to clear storage policy cache: %w", err)
	}
	return nil
}

func (c *storagePolicyClient) Upsert(ctx context.Context, policy *ent.StoragePolicy) (*ent.StoragePolicy, error) {
	if policy.Type == types.PolicyTypeLoadBalance {
		parents, err := c.ListPolicyByType(ctx, types.PolicyTypeLoadBalance)
		if err != nil {
			return nil, err
		}
		for _, parent := range parents {
			if parent.ID == policy.ID || parent.Settings == nil {
				continue
			}
			for _, id := range parent.Settings.BalancedPolicies {
				if id == policy.ID {
					return nil, fmt.Errorf("cannot convert a referenced physical destination into a load balancing policy")
				}
			}
		}
		if policy.Settings == nil || len(policy.Settings.BalancedPolicies) == 0 {
			return nil, fmt.Errorf("select at least one physical storage policy")
		}
		seen := map[int]bool{}
		for _, id := range policy.Settings.BalancedPolicies {
			if id == policy.ID || seen[id] {
				return nil, fmt.Errorf("invalid or duplicate load balancing destination")
			}
			destination, err := c.GetPolicyByID(ctx, id)
			if err != nil || destination.Type == types.PolicyTypeLoadBalance {
				return nil, fmt.Errorf("load balancing destinations must be physical storage policies")
			}
			seen[id] = true
		}
	}
	var nodeId *int
	if policy.NodeID != 0 {
		nodeId = &policy.NodeID
	}
	if policy.ID == 0 {
		p, err := c.client.StoragePolicy.
			Create().
			SetName(policy.Name).
			SetType(policy.Type).
			SetServer(policy.Server).
			SetBucketName(policy.BucketName).
			SetIsPrivate(policy.IsPrivate).
			SetAccessKey(policy.AccessKey).
			SetSecretKey(policy.SecretKey).
			SetMaxSize(policy.MaxSize).
			SetDirNameRule(policy.DirNameRule).
			SetFileNameRule(policy.FileNameRule).
			SetSettings(policy.Settings).
			SetNillableNodeID(nodeId).
			Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create storage policy: %w", err)
		}
		return p, nil
	}

	updateQuery := c.client.StoragePolicy.UpdateOne(policy).
		SetName(policy.Name).
		SetType(policy.Type).
		SetServer(policy.Server).
		SetBucketName(policy.BucketName).
		SetIsPrivate(policy.IsPrivate).
		SetSecretKey(policy.SecretKey).
		SetMaxSize(policy.MaxSize).
		SetDirNameRule(policy.DirNameRule).
		SetFileNameRule(policy.FileNameRule).
		SetSettings(policy.Settings).
		SetNillableNodeID(nodeId)

	if policy.Type != types.PolicyTypeOd {
		updateQuery.SetAccessKey(policy.AccessKey)
	}

	p, err := updateQuery.Save(ctx)

	// Clear cache
	if err := c.cache.Delete(StoragePolicyCacheKey, strconv.Itoa(policy.ID)); err != nil {
		return nil, fmt.Errorf("failed to clear storage policy cache: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update storage policy: %w", err)
	}
	return p, nil

}

func (c *storagePolicyClient) GetByGroup(ctx context.Context, group *ent.Group) (*ent.StoragePolicy, error) {
	val, skipCache := ctx.Value(SkipStoragePolicyCache{}).(bool)
	skipCache = skipCache && val

	res, err := withStoragePolicyEagerLoading(ctx, c.client.Group.QueryStoragePolicies(group)).WithNode().First(ctx)
	if err != nil {
		return nil, fmt.Errorf("get storage policies: %w", err)
	}

	return res, nil
}

// GetPolicyByID returns the storage policy by id.
func (c *storagePolicyClient) GetPolicyByID(ctx context.Context, id int) (*ent.StoragePolicy, error) {
	val, skipCache := ctx.Value(SkipStoragePolicyCache{}).(bool)
	skipCache = skipCache && val

	// Try to read from cache
	if c.cache != nil && !skipCache {
		if res, ok := c.cache.Get(StoragePolicyCacheKey + strconv.Itoa(id)); ok {
			cached := res.(ent.StoragePolicy)
			return &cached, nil
		}
	}

	res, err := withStoragePolicyEagerLoading(ctx, c.client.StoragePolicy.Query().Where(storagepolicy.ID(id))).WithNode().First(ctx)
	if err != nil {
		return nil, fmt.Errorf("get storage policy: %w", err)
	}

	// Write to cache
	if c.cache != nil && !skipCache {
		_ = c.cache.Set(StoragePolicyCacheKey+strconv.Itoa(id), *res, -1)
	}

	return res, nil
}

func (c *storagePolicyClient) ListPolicyByType(ctx context.Context, t types.PolicyType) ([]*ent.StoragePolicy, error) {
	policies, err := c.client.StoragePolicy.Query().Where(storagepolicy.TypeEQ(string(t))).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list storage policies: %w", err)
	}

	return policies, nil
}

func (c *storagePolicyClient) UpdateAccessKey(ctx context.Context, policy *ent.StoragePolicy, token string) error {
	_, err := c.client.StoragePolicy.UpdateOne(policy).SetAccessKey(token).Save(ctx)
	if err != nil {
		return fmt.Errorf("faield to update access key in DB: %w", err)
	}

	// Clear cache
	if err := c.cache.Delete(StoragePolicyCacheKey, strconv.Itoa(policy.ID)); err != nil {
		return fmt.Errorf("failed to clear storage policy cache: %w", err)
	}

	return nil
}

func (c *storagePolicyClient) ListPolicies(ctx context.Context, args *ListPolicyParameters) (*ListPolicyResult, error) {
	query := c.client.StoragePolicy.Query().WithNode()
	if args.Type != "" {
		query = query.Where(storagepolicy.TypeEQ(string(args.Type)))
	}
	query.Order(getStoragePolicyOrderOption(args)...)

	// Count total items
	total, err := query.Clone().
		Count(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := withStoragePolicyEagerLoading(ctx, query).Limit(args.PageSize).Offset(args.Page * args.PageSize).All(ctx)
	if err != nil {
		return nil, err
	}

	return &ListPolicyResult{
		PaginationResults: &PaginationResults{
			TotalItems: total,
			Page:       args.Page,
			PageSize:   args.PageSize,
		},
		Policies: policies,
	}, nil
}

func getStoragePolicyOrderOption(args *ListPolicyParameters) []storagepolicy.OrderOption {
	orderTerm := getOrderTerm(args.Order)
	switch args.OrderBy {
	case storagepolicy.FieldUpdatedAt:
		return []storagepolicy.OrderOption{storagepolicy.ByUpdatedAt(orderTerm), storagepolicy.ByID(orderTerm)}
	default:
		return []storagepolicy.OrderOption{storagepolicy.ByID(orderTerm)}
	}
}

func withStoragePolicyEagerLoading(ctx context.Context, query *ent.StoragePolicyQuery) *ent.StoragePolicyQuery {
	if _, ok := ctx.Value(LoadStoragePolicyGroup{}).(bool); ok {
		query = query.WithGroups(func(gq *ent.GroupQuery) {
			withGroupEagerLoading(ctx, gq)
		})
	}
	return query
}
