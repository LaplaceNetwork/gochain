package eth

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var client Client

func init() {
	client = New("https://ropsten.infura.io/OTFK50Z1PCljMOeEAlA9")
}

func TestGasPrice(t *testing.T) {
	price, err := client.SuggestGasPrice()

	assert.NoError(t, err)

	println(fmt.Sprintf("%d", price))
}
