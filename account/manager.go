package account

import "github.com/AgnopraxLab/D2PFuzz/config"

// AccountManager manages polling different accounts
type AccountManager struct {
	accounts    []config.Account
	currentFrom int // Current sender account index
	currentTo   int // Current receiver account index
}

// NewAccountManager creates new account manager
func NewAccountManager(accounts []config.Account) *AccountManager {
	return &AccountManager{
		accounts:    accounts,
		currentFrom: 0,
		currentTo:   1,
	}
}

// GetNextAccountPair gets next account pair (sender and receiver)
func (am *AccountManager) GetNextAccountPair() (from config.Account, to config.Account) {
	from = am.accounts[am.currentFrom]
	to = am.accounts[am.currentTo]

	// Update indices to ensure different accounts are used next time
	am.currentFrom = (am.currentFrom + 1) % len(am.accounts)
	am.currentTo = (am.currentTo + 1) % len(am.accounts)

	// Ensure sender and receiver are not the same account
	if am.currentFrom == am.currentTo {
		am.currentTo = (am.currentTo + 1) % len(am.accounts)
	}

	return from, to
}

// GetAccountByIndex gets account by index
func (am *AccountManager) GetAccountByIndex(index int) config.Account {
	if index < 0 || index >= len(am.accounts) {
		return am.accounts[0] // Default to return first account
	}
	return am.accounts[index]
}

// GetTotalAccounts gets total number of accounts
func (am *AccountManager) GetTotalAccounts() int {
	return len(am.accounts)
}

