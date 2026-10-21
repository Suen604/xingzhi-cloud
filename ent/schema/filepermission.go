package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// FilePermission is an explicit, inheritable grant to an authenticated user.
type FilePermission struct{ ent.Schema }

func (FilePermission) Fields() []ent.Field {
	return []ent.Field{
		field.Int("file_id").Positive(),
		field.Int("user_id").Positive(),
		field.Enum("role").Values("viewer", "editor"),
	}
}

func (FilePermission) Indexes() []ent.Index {
	return []ent.Index{index.Fields("file_id", "user_id").Unique(), index.Fields("user_id")}
}
