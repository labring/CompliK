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

package adminauth

import (
	"net/http"
	"os"
	"strings"
)

const (
	UsernameEnv = "ADMIN_BASIC_AUTH_USERNAME"
	PasswordEnv = "ADMIN_BASIC_AUTH_PASSWORD"
)

type BasicAuth struct {
	Username string
	Password string
}

func FromValues(username, password string) BasicAuth {
	resolvedUsername := resolveValue(username)
	resolvedPassword := resolveValue(password)
	if resolvedUsername == "" {
		resolvedUsername = strings.TrimSpace(os.Getenv(UsernameEnv))
	}
	if resolvedPassword == "" {
		resolvedPassword = strings.TrimSpace(os.Getenv(PasswordEnv))
	}
	return BasicAuth{
		Username: resolvedUsername,
		Password: resolvedPassword,
	}
}

func (a BasicAuth) Apply(req *http.Request) {
	if req == nil || strings.TrimSpace(a.Username) == "" || strings.TrimSpace(a.Password) == "" {
		return
	}
	req.SetBasicAuth(a.Username, a.Password)
}

func resolveValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "${") && strings.HasSuffix(trimmed, "}") {
		return strings.TrimSpace(os.Getenv(strings.TrimSuffix(strings.TrimPrefix(trimmed, "${"), "}")))
	}
	return trimmed
}
