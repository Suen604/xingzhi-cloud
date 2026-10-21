package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

type AbuseReport struct{ ent.Schema }

func (AbuseReport) Fields() []ent.Field {
	return []ent.Field{
		field.Int("reporter_id").Positive(),
		field.Int("share_id").Positive(),
		field.String("reason").MaxLen(2000),
		field.Enum("status").Values("open", "resolved", "dismissed").Default("open"),
		field.String("resolution").MaxLen(2000).Optional(),
	}
}
func (AbuseReport) Mixin() []ent.Mixin { return []ent.Mixin{CommonMixin{}} }
