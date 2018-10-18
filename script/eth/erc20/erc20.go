package erc20

import (
	"encoding/hex"
	"fmt"

	"github.com/laplacenetwork/gochain/script/eth"
)

const (
	signBalanceOf         = "balanceOf(address)"
	signTotalSupply       = "totalSupply()"
	signTransfer          = "transfer(address,uint256)"
	signTransferFrom      = "transferFrom(address,address,uint256)"
	signApprove           = "approve(address,uint256)"
	signName              = "name()"
	signSymbol            = "symbol()"
	signAllowance         = "allowance(address,address)"
	eventTransfer         = "Transfer(address,address,uint256)"
	decimals              = "decimals()"
	signTransferOwnership = "transferOwnership(address)"
)

// Method/Event id
var (
	TransferID          = eth.SignABI(signTransfer)
	BalanceOfID         = eth.SignABI(signBalanceOf)
	Decimals            = eth.SignABI(decimals)
	TransferFromID      = eth.SignABI(signTransferFrom)
	ApproveID           = eth.SignABI(signApprove)
	TotalSupplyID       = eth.SignABI(signTotalSupply)
	AllowanceID         = eth.SignABI(signAllowance)
	TransferOwnershipID = eth.SignABI(signTransferOwnership)
)

// BalanceOf create erc20 balanceof abi string
func BalanceOf(address string) string {
	address = eth.PackNumeric(address, 32)

	return fmt.Sprintf("0x%s%s", BalanceOfID, address)
}

// GetDecimals .
func GetDecimals() string {
	return fmt.Sprintf("0x%s", Decimals)
}

// GetTotalSupply .
func GetTotalSupply() string {
	return fmt.Sprintf("0x%s", TotalSupplyID)
}

// GetName .
func GetName() string {
	return "0x" + eth.SignABI(signName)
}

// GetSignSymbol .
func GetSignSymbol() string {
	return "0x" + eth.SignABI(signSymbol)
}

// Transfer .
func Transfer(to string, value string) ([]byte, error) {
	to = eth.PackNumeric(to, 32)
	value = eth.PackNumeric(value, 32)

	data := fmt.Sprintf("%s%s%s", eth.SignABI(signTransfer), to, value)

	return hex.DecodeString(data)
}

// TransferFrom .
func TransferFrom(from, to string, value string) ([]byte, error) {
	from = eth.PackNumeric(from, 32)
	to = eth.PackNumeric(to, 32)
	value = eth.PackNumeric(value, 32)

	data := fmt.Sprintf("%s%s%s%s", TransferFromID, from, to, value)

	return hex.DecodeString(data)
}

// Approve .
func Approve(to string, value string) ([]byte, error) {
	to = eth.PackNumeric(to, 32)
	value = eth.PackNumeric(value, 32)

	data := fmt.Sprintf("%s%s%s", ApproveID, to, value)

	return hex.DecodeString(data)
}

// Allowance .
func Allowance(from, to string) ([]byte, error) {
	from = eth.PackNumeric(from, 32)
	to = eth.PackNumeric(to, 32)

	data := fmt.Sprintf("%s%s%s", AllowanceID, to, to)

	return hex.DecodeString(data)
}

// TransferOwnership .
func TransferOwnership(to string) ([]byte, error) {
	to = eth.PackNumeric(to, 32)
	data := fmt.Sprintf("%s%s", TransferOwnershipID, to)

	return hex.DecodeString(data)
}
