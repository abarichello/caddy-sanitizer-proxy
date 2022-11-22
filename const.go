package filter

import "errors"

var (
	FORUM_CAGR_HOST = "forum.cagr.ufsc.br/" // URL do serviço que as requisições serão encaminhadas após o filtro
	ErrXSSDetected  = errors.New("XSS detected")
)

const (
	BEHAVIOR_FILTER  = "filter"  // Filtra o conteúdo da requisição antes de redirecioná-lo para o CAGR
	BEHAVIOR_DISCARD = "discard" // Descarta a requisição assim que um elemento não permitido é detectado
)
