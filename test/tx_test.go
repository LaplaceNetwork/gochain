package test

import (
	"bytes"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dynamicgo/fixed"

	"github.com/laplacenetwork/gochain/script/eth/erc20"
	"github.com/laplacenetwork/gochain/tx"

	_ "github.com/laplacenetwork/gochain/tx/provider"
	"github.com/laplacenetwork/key"
	_ "github.com/laplacenetwork/key/encryptor"
	_ "github.com/laplacenetwork/key/provider"
)

var k key.Key
var ethnode = "https://ropsten.infura.io/OTFK50Z1PCljMOeEAlA9"

func init() {
	var err error
	k, err = key.New("eth")

	if err != nil {
		panic(err)
	}

	buff, err := ioutil.ReadFile("../../conf/keystore/2.json")

	if err != nil {
		panic(err)
	}

	err = key.Decrypt("web3.standard", k, map[string]string{
		"password": "test",
	}, bytes.NewBuffer(buff))

	if err != nil {
		panic(err)
	}
}

func TestTransfer(t *testing.T) {
	txid, err := tx.Transfer("eth", ethnode, k, k.Address(), fixed.FromFloat(big.NewFloat(0.0001), 18), nil)

	require.NoError(t, err)

	println(txid)
}

func TestCall(t *testing.T) {

	val := fixed.FromFloat(big.NewFloat(100), 18)

	code, err := erc20.Transfer(k.Address(), val.HexValue())

	require.NoError(t, err)

	txid, err := tx.Call("eth", ethnode, k, "0x21a279110818fb675c9212513dff9aaf753f31a3", code, nil)

	require.NoError(t, err)

	println(txid)
}
