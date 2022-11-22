package filter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeXSS(t *testing.T) {
	var modified bool
	var sanitizedTxt string

	// Teste de sanitização de um XSS simples
	modified, sanitizedTxt = SanitizeXSS("<script>alert('XSS')</script>")
	assert.True(t, modified, "Filtra XSS simples")
	assert.Equal(t, "", sanitizedTxt, "Retorno de string filtrada deve ser vazio")

	// Teste de sanitização de elementos HTML imagem
	modified, sanitizedTxt = SanitizeXSS("<img src='https://www.gov.br/participamaisbrasil/blob/ver/8098?w=0&h=0'></img>")
	assert.True(t, modified, "Filtra elementos de imagem")
	assert.Equal(t, "", sanitizedTxt, "Retorno de string filtrada deve ser vazio")

	// Teste de sanitização de elementos HTML imagem com a presença de texto
	modified, sanitizedTxt = SanitizeXSS("<img src='https://www.gov.br/participamaisbrasil/blob/ver/8098?w=0&h=0'>Logo UFSC</img>")
	assert.True(t, modified, "Filtra elementos de imagem misto com texto")
	assert.Equal(t, "Logo UFSC", sanitizedTxt, "Retorno de string filtrada deve ser vazio")

	// Teste de sanitização de um código do tipo Injetor apresentado no apêndice do trabalho
	modified, sanitizedTxt = SanitizeXSS(
		"<script>setTimeout(()=>{var t=document.getElementsByTagName('span');for(tag of t){if(tag.innerText.startsWith('//40')){eval(tag.innerText)}}},600)</script>",
	)
	assert.True(t, modified, "Filtra Payload de XSS")
	assert.Equal(t, "", sanitizedTxt, "Retorno de string filtrada deve ser vazio")
}
