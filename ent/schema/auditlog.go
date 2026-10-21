package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type AuditLog struct{ ent.Schema }

func (AuditLog) Fields() []ent.Field {
	return []ent.Field{
		field.Int("actor_id").Default(0),
		field.String("action"),
		field.String("resource").Optional(),
		field.String("ip").Optional(),
		field.Int("status").Default(0),
	}
}
func (AuditLog) Mixin() []ent.Mixin { return []ent.Mixin{CommonMixin{}} }
func (AuditLog) Indexes() []ent.Index {
	return []ent.Index{index.Fields("actor_id", "created_at"), index.Fields("action", "created_at")}
}
