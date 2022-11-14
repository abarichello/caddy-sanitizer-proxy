package filter

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Filter{})
	httpcaddyfile.RegisterHandlerDirective("xss-filter", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	t := new(Filter)
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

// Main entrypoint for a request
func (filter *Filter) ServeHTTP(w http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	filter.logger.Info("URL: " + req.URL.String())

	// Copy original body before parsing multipart form
	buf, _ := io.ReadAll(req.Body)
	// Buffer to be used in the request forwarding
	originalReadCloser := io.NopCloser(bytes.NewBuffer(buf))
	// Buffer to be consumed by the ParseMultipartForm function
	multipartReadCloser := io.NopCloser(bytes.NewBuffer(buf))
	req.Body = multipartReadCloser

	req.ParseMultipartForm(0)
	if req.Form.Has(FORM_TITLE) {
		filter.logger.Info("Título: \n" + req.FormValue(FORM_TITLE))
	}

	client := http.Client{Timeout: time.Minute}
	cagrForum := "forum.cagr.ufsc.br"
	cagrURL, err := url.Parse("http://" + cagrForum + "/escreverMensagem.jsf?topicoId=2600424")
	if err != nil {
		return err
	}
	cagrRequest := http.Request{
		Method:        req.Method,
		URL:           cagrURL,
		Header:        req.Header,
		Body:          originalReadCloser,
		ContentLength: req.ContentLength,
		Host:          cagrForum,
		Form:          req.Form,
		PostForm:      req.PostForm,
		MultipartForm: req.MultipartForm,
		RemoteAddr:    req.RemoteAddr,
		TLS:           req.TLS,
	}
	fmt.Printf("request: %v\n", cagrRequest)
	response, err := client.Do(&cagrRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	fmt.Printf("response: %v\n", response)
	filter.logger.Info("Response: " + response.Status)
	return next.ServeHTTP(w, req)
}

// Interface guards: https://caddyserver.com/docs/extending-caddy#interface-guards
var (
	_ caddy.Provisioner           = (*Filter)(nil)
	_ caddyhttp.MiddlewareHandler = (*Filter)(nil)
)
