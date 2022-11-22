package filter

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("xss-filter", parseCaddyfile)
}

// parseCaddyfile fará o parsing da diretiva 'xss-filter' que é criada por este módulo.
// Diretivas padrões do servidor Caddy também podem ser utilizadas em conjunto com este módulo
// https://caddyserver.com/docs/caddyfile/directives
//
//	XSSFilter {
//	    behavior <"filter" or "discard">
//	    forms [<form titles to be checked>]
//	}
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return parseCaddyfileWithDispenser(h.Dispenser)
}

func parseCaddyfileWithDispenser(h *caddyfile.Dispenser) (*XSSFilter, error) {
	var b XSSFilter

	h.NextArg() // skip block beginning: "xss-filter"
	for h.NextBlock(0) {
		switch h.Val() {
		case "behavior":
			if !h.AllArgs(&b.Behavior) {
				return nil, h.ArgErr()
			}
			if b.Behavior == "filter" || b.Behavior == "discard" {
				continue
			} else {
				return nil, h.ArgErr()
			}
		case "forms":
			b.Forms = h.RemainingArgs()
			if len(b.Forms) == 0 {
				return nil, h.ArgErr()
			}
		default:
			return nil, h.Errf("%s not a valid XSSFilter option", h.Val())
		}
	}

	return &b, nil
}
