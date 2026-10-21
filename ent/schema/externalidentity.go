package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type ExternalIdentity struct{ ent.Schema }

func (ExternalIdentity) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id").Positive(),
		field.String("provider"),
		field.String("subject").MaxLen(255),
	}
}
func (ExternalIdentity) Mixin() []ent.Mixin { return []ent.Mixin{CommonMixin{}} }
func (ExternalIdentity) Indexes() []ent.Index {
	return []ent.Index{index.Fields("provider", "subject").Unique(), index.Fields("user_id", "provider").Unique()}
}
