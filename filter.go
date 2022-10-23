package filter

import "github.com/caddyserver/caddy/v2"

func init() {
	caddy.RegisterModule(Filter{})
}

// Gizmo is an example; put your own type here.
type Filter struct {
}

// CaddyModule returns the Caddy module information.
func (Filter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "filter",
		New: func() caddy.Module { return new(Filter) },
	}
}
