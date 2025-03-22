package repository

import (
	"errors"
)

type AccessPolicyRepository struct {
	policies map[string][]string
}

func NewAccessPolicyRepository() AccessPolicies {
	return AccessPolicyRepository{policies: map[string][]string{
		"USER":             {"/api.chat/SendMessage", "/api.chat/Create"},
		"ADMIN":            {"/api.chat/SendMessage", "/api.chat/Delete", "/api.chat/Create"},
		"ROLE_UNSPECIFIED": {"/api.chat/SendMessage"}}}
}

func (a AccessPolicyRepository) Check(path string, role string) error {
	paths, ok := a.policies[role]
	if !ok {
		return errors.New("access role not found")
	}

	for _, p := range paths {
		if p == path {
			return nil
		}
	}

	return errors.New("access policy not found")
}
