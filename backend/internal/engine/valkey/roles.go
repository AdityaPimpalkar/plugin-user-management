package valkey

import (
	"fmt"
	"strings"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

const (
	roleRead      = "read"
	roleReadWrite = "readWrite"
	rolePubSub    = "pubsub"
)

// The roles the plugin grants. All apply to the whole instance: Valkey has no
// databases in cluster mode. None reaches @admin or @dangerous commands
// (ACL, CONFIG, FLUSHALL, KEYS, ...), whatever the user is also granted.
var roleCatalog = []engine.Role{
	{Name: roleRead, Scope: engine.ScopeCluster, Description: "Read all keys (@read)."},
	{Name: roleReadWrite, Scope: engine.ScopeCluster, Description: "Read and write all keys, with transactions and scripts (@read, @write, @transaction and @scripting).", Includes: []string{roleRead}},
	{Name: rolePubSub, Scope: engine.ScopeCluster, Description: "Publish and subscribe to all channels (@pubsub)."},
}

// baseCommands are allowed to every user: the connection handshake, and the
// commands cluster-aware clients run to discover and follow the topology.
var baseCommands = []string{
	"@connection",
	"asking",
	"readonly",
	"readwrite",
	"cluster|info",
	"cluster|myid",
	"cluster|nodes",
	"cluster|shards",
	"cluster|slots",
}

// deniedCommands are denied to every user, after its allowed commands.
var deniedCommands = []string{"@admin", "@dangerous"}

var roleCommands = map[string][]string{
	roleRead:      {"@read"},
	roleReadWrite: {"@read", "@write", "@transaction", "@scripting"},
	rolePubSub:    {"@pubsub"},
}

// allKeys and allChannels are the key and channel patterns of granted users.
const (
	allKeys     = "*"
	allChannels = "*"
)

// normalizeRoles validates grants and returns them as fromRules reports
// them: readWrite includes read, so read is dropped next to it.
func normalizeRoles(grants []engine.RoleGrant) ([]engine.RoleGrant, error) {
	if len(grants) == 0 {
		return nil, fmt.Errorf("%w: at least one role is required", engine.ErrInvalid)
	}
	granted := map[string]bool{}
	for _, g := range grants {
		if _, ok := roleCommands[g.Role]; !ok {
			return nil, fmt.Errorf("%w: role %q can't be granted", engine.ErrInvalid, g.Role)
		}
		if g.Database != "" {
			return nil, fmt.Errorf("%w: role %q applies to the whole instance, not to a database", engine.ErrInvalid, g.Role)
		}
		granted[g.Role] = true
	}
	if granted[roleReadWrite] {
		delete(granted, roleRead)
	}
	out := make([]engine.RoleGrant, 0, len(granted))
	for _, r := range roleCatalog {
		if granted[r.Name] {
			out = append(out, engine.RoleGrant{Role: r.Name})
		}
	}
	return out, nil
}

// permissions are the ACL rules of a user granted normalized roles.
type permissions struct {
	allow    []string
	deny     []string
	keys     []string
	channels []string
}

func toPermissions(roles []engine.RoleGrant) permissions {
	p := permissions{allow: append([]string{}, baseCommands...), deny: deniedCommands}
	seen := map[string]bool{}
	for _, g := range roles {
		for _, c := range roleCommands[g.Role] {
			if !seen[c] {
				seen[c] = true
				p.allow = append(p.allow, c)
			}
		}
		switch g.Role {
		case roleRead, roleReadWrite:
			p.keys = []string{allKeys}
		case rolePubSub:
			p.channels = []string{allChannels}
		}
	}
	return p
}

// fromRules returns the roles granted by the rules of an aclfile entry, as
// the operator renders them ("+@read ~* -@admin ..."). Rules the plugin
// never writes, such as +@all, grant no role.
func fromRules(rules []string) []engine.RoleGrant {
	allowed := map[string]bool{}
	for _, r := range rules {
		if c, ok := strings.CutPrefix(r, "+@"); ok {
			allowed[c] = true
		}
	}
	roles := []engine.RoleGrant{}
	switch {
	case allowed["write"]:
		roles = append(roles, engine.RoleGrant{Role: roleReadWrite})
	case allowed["read"]:
		roles = append(roles, engine.RoleGrant{Role: roleRead})
	}
	if allowed["pubsub"] {
		roles = append(roles, engine.RoleGrant{Role: rolePubSub})
	}
	return roles
}
