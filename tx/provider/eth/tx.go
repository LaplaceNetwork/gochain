package eth

import (
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/dynamicgo/fixed"

	"github.com/dynamicgo/xerrors"

	ethrpc "github.com/laplacenetwork/gochain/rpc/eth"
	"github.com/laplacenetwork/gochain/tx"
	"github.com/laplacenetwork/gochain/tx/internal/rlp"
	"github.com/laplacenetwork/key"
	"github.com/openzknetwork/sha3"
)

var (
	transferGasLimits = big.NewInt(21000)
	contractGasLimits = big.NewInt(55818)
)

// Tx .
type Tx struct {
	AccountNonce uint64    `json:"nonce"    gencodec:"required"`
	Price        *big.Int  `json:"gasPrice" gencodec:"required"`
	GasLimit     *big.Int  `json:"gas"      gencodec:"required"`
	Recipient    *[20]byte `json:"to"       rlp:"nil"` // nil means contract creation
	Amount       *big.Int  `json:"value"    gencodec:"required"`
	Payload      []byte    `json:"input"    gencodec:"required"`
	V            *big.Int  `json:"v" gencodec:"required"`
	R            *big.Int  `json:"r" gencodec:"required"`
	S            *big.Int  `json:"s" gencodec:"required"`
}

// NewTx create new eth tx
func newTx(nonce uint64, to string, amount, gasPrice *fixed.Number, gasLimit *big.Int, data []byte) *Tx {

	var recpoint *[20]byte

	if to != "" {
		var recipient [20]byte

		to = strings.TrimPrefix(to, "0x")

		toBytes, _ := hex.DecodeString(to)

		copy(recipient[:], toBytes)

		recpoint = &recipient
	}

	tx := &Tx{
		AccountNonce: nonce,
		Recipient:    recpoint,
		Payload:      data,
		GasLimit:     gasLimit,
		Price:        gasPrice.ValueBigInteger(),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}

	if amount != nil {
		tx.Amount = amount.ValueBigInteger()
	}

	return tx
}

// Sign .
func (tx *Tx) Sign(key key.Key) (string, error) {
	hw := sha3.NewKeccak256()

	rlp.Encode(hw, []interface{}{
		tx.AccountNonce,
		tx.Price,
		tx.GasLimit,
		tx.Recipient,
		tx.Amount,
		tx.Payload,
	})

	var hash [32]byte

	hw.Sum(hash[:0])

	sig, err := key.Sign(hash[:])

	if err != nil {
		return "", err
	}

	tx.R = new(big.Int).SetBytes(sig[:32])
	tx.S = new(big.Int).SetBytes(sig[32:64])
	tx.V = new(big.Int).SetBytes(sig[64:])

	return tx.Hash(), nil
}

// Encode .
func (tx *Tx) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(tx)
}

func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

// Hash get tx hash string
func (tx *Tx) Hash() string {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, tx)
	return "0x" + hex.EncodeToString(hw.Sum(nil))
}

type txProvider struct {
}

func (provider *txProvider) Name() string {
	return "eth"
}

func (provider *txProvider) Transfer(node string, key key.Key, to string, amount *fixed.Number, property tx.Property) (string, error) {
	gasLimit := transferGasLimits

	if _, ok := property["gasLimits"]; ok {
		limits, ok := property["gasLimits"].(*big.Int)

		if !ok {
			return "", xerrors.Wrapf(tx.ErrProperty, "gasLimits must be *big.Int")
		}

		gasLimit = limits
	}

	return provider.doCall(node, key, to, gasLimit, amount, nil, property)
}

func (provider *txProvider) doCall(node string, key key.Key, to string, gasLimits *big.Int, amount *fixed.Number, script []byte, property tx.Property) (string, error) {

	if property == nil {
		property = make(map[string]interface{})
	}

	if !key.Provider().ValidAddress(to) {
		return "", xerrors.Wrapf(tx.ErrAddress, "invalid transfer to address %s", to)
	}

	client := ethrpc.New(node)

	var gasPrice *fixed.Number
	var err error

	if _, ok := property["gasPrice"]; ok {
		price, ok := property["gasPrice"].(string)

		if !ok {
			return "", xerrors.Wrapf(tx.ErrProperty, "gasPrice must be string")
		}

		gasPrice, err = fixed.FromHex(price, 18)
	} else {
		gasPrice, err = client.SuggestGasPrice()

	}

	if err != nil {
		return "", xerrors.Wrapf(err, "get gas price error")
	}

	if amount == nil {
		if _, ok := property["value"]; ok {
			value, ok := property["value"].(string)

			if !ok {
				return "", xerrors.Wrapf(tx.ErrProperty, "value must be string")
			}

			amount, err = fixed.FromHex(value, 18)

			if err != nil {
				return "", xerrors.Wrapf(err, "decode value error")
			}
		}
	}

	nonce, err := client.Nonce(key.Address())

	if err != nil {
		return "", xerrors.Wrapf(err, "get address %s nonce error", key.Address())
	}

	tx := newTx(nonce, to, amount, gasPrice, gasLimits, script)

	txid, err := tx.Sign(key)

	if err != nil {
		return "", xerrors.Wrapf(err, "sign tx error")
	}

	rawtx, err := tx.Encode()

	if err != nil {
		return "", xerrors.Wrapf(err, "encode tx error")
	}

	txid, err = client.SendRawTransaction(rawtx)

	if err != nil {
		return "", xerrors.Wrapf(err, "send raw tx error")
	}

	return txid, nil
}

func (provider *txProvider) Call(node string, key key.Key, to string, script []byte, property tx.Property) (string, error) {
	gasLimit := contractGasLimits

	if _, ok := property["gasLimits"]; ok {
		limits, ok := property["gasLimits"].(*big.Int)

		if !ok {
			return "", xerrors.Wrapf(tx.ErrProperty, "gasLimits must be *big.Int")
		}

		gasLimit = limits
	}

	return provider.doCall(node, key, to, gasLimit, nil, script, property)
}

func init() {
	tx.RegisterProvider(&txProvider{})
}
