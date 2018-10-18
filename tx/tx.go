package tx

import (
	"errors"

	"github.com/dynamicgo/fixed"

	"github.com/dynamicgo/injector"
	"github.com/dynamicgo/xerrors"
	"github.com/laplacenetwork/key"
)

// Errors
var (
	ErrProvider = errors.New("unknown provider")
	ErrAddress  = errors.New("invalid address")
	ErrProperty = errors.New("invalid property value")
)

// Property .
type Property map[string]interface{}

// Provider .
type Provider interface {
	Name() string                                                                                         // provider offical name
	Transfer(node string, key key.Key, to string, value *fixed.Number, property Property) (string, error) // transfer global asset
}

// CallableProvider .
type CallableProvider interface {
	Provider
	Call(node string, key key.Key, to string, script []byte, property Property) (string, error)
}

// DeployableProvider .
type DeployableProvider interface {
	Provider
	Deploy(node string, key key.Key, script []byte) (string, error)
	ContractAddress(node string, tx string) (string, error)
}

// RegisterProvider register provider
func RegisterProvider(provider Provider) {
	injector.Register(provider.Name(), provider)
}

// Transfer .
func Transfer(providerName string, node string, key key.Key, to string, value *fixed.Number, property Property) (string, error) {
	var provider Provider
	if !injector.Get(providerName, &provider) {
		return "", xerrors.Wrapf(ErrProvider, "unknown provider %s", providerName)
	}

	return provider.Transfer(node, key, to, value, property)
}

// Call call smart contract script
func Call(providerName string, node string, key key.Key, to string, script []byte, property Property) (string, error) {
	var provider CallableProvider
	if !injector.Get(providerName, &provider) {
		return "", xerrors.Wrapf(ErrProvider, "unknown provider %s", providerName)
	}

	return provider.Call(node, key, to, script, property)
}

// Deploy deploy contract
func Deploy(providerName string, node string, key key.Key, script []byte) (string, error) {
	var provider DeployableProvider
	if !injector.Get(providerName, &provider) {
		return "", xerrors.Wrapf(ErrProvider, "unknown provider %s", providerName)
	}

	return provider.Deploy(node, key, script)
}

// ContractAddress get deployed contract address
func ContractAddress(providerName string, node string, deployTx string) (string, error) {
	var provider DeployableProvider
	if !injector.Get(providerName, &provider) {
		return "", xerrors.Wrapf(ErrProvider, "unknown provider %s", providerName)
	}

	return provider.ContractAddress(node, deployTx)
}
