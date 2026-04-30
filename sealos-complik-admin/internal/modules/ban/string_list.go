package ban

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
)

type StringList []string

func (s StringList) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "[]", nil
	}

	payload, err := json.Marshal([]string(s))
	if err != nil {
		return nil, fmt.Errorf("marshal string list: %w", err)
	}

	return string(payload), nil
}

func (s *StringList) Scan(value any) error {
	if s == nil {
		return fmt.Errorf("scan string list: nil target")
	}

	switch typed := value.(type) {
	case nil:
		*s = nil
		return nil
	case []byte:
		return s.unmarshalBytes(typed)
	case string:
		return s.unmarshalBytes([]byte(typed))
	default:
		return fmt.Errorf("scan string list: unsupported type %T", value)
	}
}

func (s *StringList) unmarshalBytes(value []byte) error {
	trimmed := strings.TrimSpace(string(value))
	if trimmed == "" {
		*s = nil
		return nil
	}

	var items []string
	if err := json.Unmarshal([]byte(trimmed), &items); err != nil {
		return fmt.Errorf("unmarshal string list: %w", err)
	}

	*s = items
	return nil
}
