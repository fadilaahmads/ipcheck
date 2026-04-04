package utils_test

import (
	"testing"

	"ipcheck/internal/utils"
)

func TestMinVal(t *testing.T) {
	tests := []struct {
		a, b int
		want int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{1, 1, 1},
		{-1, 0, -1},
		{0, -1, -1},
		{-5, -10, -10},
	}

	for _, tt := range tests {
		got := utils.MinVal(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("MinVal(%d, %d) = %d; want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
