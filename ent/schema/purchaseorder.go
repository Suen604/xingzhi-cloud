package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

type PurchaseOrder struct{ ent.Schema }

func (PurchaseOrder) Fields() []ent.Field {
	return []ent.Field{
		field.String("number").Unique(),
		field.Int("user_id").Positive(),
		field.String("provider"),
		field.String("product_id"),
		field.String("product_name"),
		field.Int64("amount").Positive(),
		field.String("currency").Default("CNY"),
		field.Enum("status").Values("pending", "paid", "fulfilled", "cancelled").Default("pending"),
		field.String("transaction_id").Optional(),
		field.Int64("storage_bytes").Default(0),
		field.Int("group_id").Default(0),
		// Resource and seller snapshots bind payment to this exact share target.
		field.Int("share_id").Default(0).NonNegative(),
		field.Int("file_id").Default(0).NonNegative(),
		field.Int("seller_id").Default(0).NonNegative(),
		field.Time("expires_at"),
	}
}
func (PurchaseOrder) Mixin() []ent.Mixin { return []ent.Mixin{CommonMixin{}} }
func (PurchaseOrder) Indexes() []ent.Index {
	return []ent.Index{index.Fields("user_id", "created_at"), index.Fields("status", "created_at"),
		index.Fields("user_id", "share_id", "status"), index.Fields("seller_id", "status", "created_at")}
}
