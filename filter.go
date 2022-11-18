package filter

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(XSSFilter{})
}

// This XSSFilter module is responsible to filtering messages sent to a website through a reverse-proxy
type XSSFilter struct {
	Behavior string
	Forms    []string

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (filter XSSFilter) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.filter",
		New: func() caddy.Module { return new(XSSFilter) },
	}
}

func (filter *XSSFilter) Provision(ctx caddy.Context) error {
	filter.logger = ctx.Logger()
	return nil
}

// Main entrypoint for a request
func (filter *XSSFilter) ServeHTTP(w http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	filter.logger.Info("XSS Filter")
	requestPath := req.URL.Path
	filter.logger.Info("Filtering path: " + requestPath)
	filter.logger.Info("Behavior: " + filter.Behavior)
	filter.logger.Info("Forms to filter: \"" + strings.Join(filter.Forms, ", ") + "\"")

	// Copy original body before parsing multipart form
	buf, _ := io.ReadAll(req.Body)
	// Buffer to be used in the request forwarding
	originalReadCloser := io.NopCloser(bytes.NewBuffer(buf))
	// Buffer to be consumed by the ParseMultipartForm function
	multipartReadCloser := io.NopCloser(bytes.NewBuffer(buf))
	req.Body = multipartReadCloser

	req.ParseMultipartForm(0)
	// if req.Form.Has(FORM_TITLE) {
	// 	filter.logger.Info("Título: " + req.FormValue(FORM_TITLE))
	// }

	client := http.Client{Timeout: time.Minute}
	cagrURL, err := url.Parse("http://" + FORUM_CAGR_HOST + requestPath)
	if err != nil {
		return err
	}
	cagrRequest := http.Request{
		Method:        req.Method,
		URL:           cagrURL,
		Header:        req.Header,
		Body:          originalReadCloser,
		ContentLength: req.ContentLength,
		Host:          FORUM_CAGR_HOST,
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
	_ caddy.Provisioner           = (*XSSFilter)(nil)
	_ caddyhttp.MiddlewareHandler = (*XSSFilter)(nil)
)
