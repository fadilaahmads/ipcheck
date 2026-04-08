package input

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseEnvFile(t *testing.T) {
	// Create a temporary directory for test files to ensure independence
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		content  string
		expected map[string]string
		wantErr  bool
	}{
		{
			name: "Happy Path - Standard pairs",
			content: `
KEY1=VALUE1
KEY2=VALUE2
`,
			expected: map[string]string{"KEY1": "VALUE1", "KEY2": "VALUE2"},
		},
		{
			name: "Comments and Whitespace",
			content: `
# This is a comment
KEY1=VALUE1

  KEY2 = VALUE2  
`,
			expected: map[string]string{"KEY1": "VALUE1", "KEY2": "VALUE2"},
		},
		{
			name: "Quoted Values",
			content: `
DB_URL="postgres://user:pass@localhost"
API_KEY='secret_key_123'
`,
			expected: map[string]string{
				"DB_URL":  "postgres://user:pass@localhost",
				"API_KEY": "secret_key_123",
			},
		},
		{
			name: "Values with multiple equals signs",
			content: `
DB_CONN=postgres://user:p@ss==word@localhost
`,
			expected: map[string]string{"DB_CONN": "postgres://user:p@ss==word@localhost"},
		},
		{
			name: "Empty values and malformed lines",
			content: `
INVALID_LINE_NO_EQUALS
=VALUE_WITH_NO_KEY
KEY_WITH_NO_VALUE=
`,
			expected: map[string]string{"KEY_WITH_NO_VALUE": ""},
		},
		{
			name:     "Empty file",
			content:  "",
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a unique temporary file for each test case
			tmpFile := filepath.Join(tmpDir, tt.name+".env")
			err := os.WriteFile(tmpFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}

			got, err := ParseEnvFile(tmpFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEnvFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ParseEnvFile() got = %v, want %v", got, tt.expected)
			}
		})
	}

	t.Run("File Not Found - Safe Failure", func(t *testing.T) {
		// Test that missing file returns empty map, not error (intended behavior)
		got, err := ParseEnvFile("this_file_definitely_does_not_exist.env")
		if err != nil {
			t.Errorf("Expected no error for missing file, got %v", err)
		}
		if len(got) != 0 {
			t.Errorf("Expected empty map for missing file, got %v", got)
		}
	})
}
