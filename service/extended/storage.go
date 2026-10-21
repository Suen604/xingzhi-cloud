package extended

import (
	"errors"
	"net/http"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/inventory/types"
	"github.com/gin-gonic/gin"
)

func UserStoragePolicies(c *gin.Context) {
	dep := dependency.FromContext(c)
	u := inventory.UserFromContext(c)
	group := u.Edges.Group
	if group == nil {
		response(c, nil, errors.New("group not loaded"))
		return
	}
	ids := []int{group.StoragePolicyID}
	if group.Settings != nil {
		ids = append(ids, group.Settings.AllowedPolicies...)
	}
	allowed := map[int]bool{}
	for _, id := range ids {
		if id > 0 {
			allowed[id] = true
		}
	}
	if c.Request.Method == http.MethodGet {
		policies := make([]map[string]any, 0, len(allowed))
		for id := range allowed {
			p, err := dep.StoragePolicyClient().GetPolicyByID(c, id)
			if err == nil {
				policies = append(policies, map[string]any{"id": p.ID, "name": p.Name, "type": p.Type})
			}
		}
		selected := 0
		if u.Settings != nil {
			selected = u.Settings.PreferredStoragePolicy
		}
		response(c, map[string]any{"items": policies, "selected": selected}, nil)
		return
	}
	var input struct {
		ID int `json:"id"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		response(c, nil, err)
		return
	}
	if input.ID != 0 && !allowed[input.ID] {
		response(c, nil, errors.New("storage policy is not assigned to your group"))
		return
	}
	if input.ID > 0 {
		if _, err := dep.StoragePolicyClient().GetPolicyByID(c, input.ID); err != nil {
			response(c, nil, errors.New("storage policy no longer exists"))
			return
		}
	}
	// Optimistic compare-and-swap preserves simultaneous profile changes.
	current, err := dep.DBClient().User.Get(c, u.ID)
	if err != nil {
		response(c, nil, err)
		return
	}
	settings := types.UserSetting{}
	if current.Settings != nil {
		settings = *current.Settings
	}
	settings.PreferredStoragePolicy = input.ID
	count, err := dep.DBClient().User.Update().Where(user.ID(current.ID), user.UpdatedAtEQ(current.UpdatedAt)).SetSettings(&settings).Save(c)
	if err == nil && count != 1 {
		err = errors.New("profile changed concurrently; retry the operation")
	}
	response(c, map[string]bool{"saved": err == nil}, err)
}
