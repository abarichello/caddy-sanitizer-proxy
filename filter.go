package filter

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Filter{})
	httpcaddyfile.RegisterHandlerDirective("xss-filter", parseCaddyfile)
}

// UnmarshalCaddyfile - this is a no-op
func (s *Filter) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	t := new(Filter)

	err := t.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}

	return t, nil
}

// This Filter module is responsible to filtering messages sent to a website through a reverse-proxy
type Filter struct {
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (filter Filter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.filter",
		New: func() caddy.Module { return new(Filter) },
	}
}

func (filter *Filter) Provision(ctx caddy.Context) error {
	filter.logger = ctx.Logger()
	return nil
}

func (filter *Filter) ServeHTTP(w http.ResponseWriter, req *http.Request, _ caddyhttp.Handler) error {
	filter.logger.Info("URL: " + req.URL.String())
	w.WriteHeader(http.StatusTeapot)
	_, err := w.Write([]byte("Filter test\n"))
	return err
}

// Interface guards: https://caddyserver.com/docs/extending-caddy#interface-guards
var (
	_ caddyhttp.MiddlewareHandler = (*Filter)(nil)
)
