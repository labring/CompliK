// Copyright 2025 CompliK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"net/http"
	"os"
	"strings"
)

const (
	AdminBasicAuthUsernameEnv = "ADMIN_BASIC_AUTH_USERNAME"
	AdminBasicAuthPasswordEnv = "ADMIN_BASIC_AUTH_PASSWORD"
)

type AdminBasicAuth struct {
	Username string
	Password string
}

func ResolveAdminBasicAuth(username, password string) AdminBasicAuth {
	resolvedUsername := resolveOptionalSecureValue(username)
	resolvedPassword := resolveOptionalSecureValue(password)
	if resolvedUsername == "" {
		resolvedUsername = strings.TrimSpace(os.Getenv(AdminBasicAuthUsernameEnv))
	}
	if resolvedPassword == "" {
		resolvedPassword = strings.TrimSpace(os.Getenv(AdminBasicAuthPasswordEnv))
	}
	return AdminBasicAuth{
		Username: resolvedUsername,
		Password: resolvedPassword,
	}
}

func (a AdminBasicAuth) Apply(req *http.Request) {
	if req == nil || strings.TrimSpace(a.Username) == "" || strings.TrimSpace(a.Password) == "" {
		return
	}
	req.SetBasicAuth(a.Username, a.Password)
}

func resolveOptionalSecureValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	resolved, err := GetSecureValue(trimmed)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(resolved)
}
