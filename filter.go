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
	initSanitizer()
	caddy.RegisterModule(XSSFilter{})
}

// O módulo XSSFilter é responsável por filtrar dados enviados a um site através de um reverse-proxy
type XSSFilter struct {
	Behavior string
	Forms    []string

	logger *zap.Logger
}

// CaddyModule retorna informação do módulo Caddy.
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

// Função responsável pela manipulação da requisição recebida
func (filter *XSSFilter) ServeHTTP(w http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	filter.logger.Info("XSS Filter")
	requestPath := req.URL.Path
	filter.logger.Info("Filtering path: " + requestPath)
	filter.logger.Info("Behavior: " + filter.Behavior)
	filter.logger.Info("Forms to filter: \"" + strings.Join(filter.Forms, ", ") + "\"")

	// Cópia do buffer a ser utilizado antes do parse feito pela função ParseMultipartForm
	buf, _ := io.ReadAll(req.Body)
	// Buffer a ser usado no redirecionamento da requisição
	originalReadCloser := io.NopCloser(bytes.NewBuffer(buf))
	// Buffer que será consumido pela função ParseMultipartForm
	multipartReadCloser := io.NopCloser(bytes.NewBuffer(buf))
	req.Body = multipartReadCloser

	req.ParseMultipartForm(0)

	for _, formName := range filter.Forms {
		if req.Form.Has(formName) {
			filter.logger.Info("Filtering form with value: " + req.FormValue(formName))
		}
	}

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
