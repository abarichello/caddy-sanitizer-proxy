package filter

import (
	"github.com/microcosm-cc/bluemonday"
)

var (
	policy *bluemonday.Policy
)

// Inicialização da política de sanitização
func initSanitizer() {
	// Para o título é utilizada a StrictPolicy que remove todo tipo de tag HTML presente no texto
	// Neste estudo de caso voltado para o CAGR esta política é a que atende melhor os requisitos
	// de filtragem do campo 'título' do fórum de mensagens
	policy = bluemonday.StrictPolicy()
	// No caso de ser necessário filtrar outros campos poderiam ser gerados outros tipos de políticas.
	// O campo de 'mensagem' do fórum permite elementos HTML para a personalização da mensagem, uma política
	// de filtragem hipotética desse campo poderia ser definida da seguinte maneira:
	//
	// Exemplo:
	// policy = bluemonday.NewPolicy()
	// policy.AllowTables()
	// policy.AllowImages()
	// policy.AllowStandardURLs()
	// ...
}

func SanitizeXSS(input string) (bool, string) {
	sanitized := policy.Sanitize(input)
	modified := sanitized != input
	return modified, sanitized
}
