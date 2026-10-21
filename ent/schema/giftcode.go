package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

type GiftCode struct{ ent.Schema }

func (GiftCode) Fields() []ent.Field {
	return []ent.Field{
		field.String("code_hash").Unique().Sensitive(),
		field.String("product_name"),
		field.Int64("storage_bytes").Default(0),
		field.Int("group_id").Default(0),
		field.Int("redeemed_by").Default(0),
		field.Time("expires_at"),
		field.Time("redeemed_at").Optional().Nillable(),
	}
}
func (GiftCode) Mixin() []ent.Mixin { return []ent.Mixin{CommonMixin{}} }
