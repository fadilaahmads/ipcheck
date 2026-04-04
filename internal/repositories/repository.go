package repositories

import (
	"context"
	"ipcheck/internal/models"
)

// Repository defines the interface for data storage and retrieval
type Repository interface {
	// SaveIP saves or updates the reputation data for a single IP
	SaveIP(ctx context.Context, result *models.EnhancedCachedResult) error

	// GetIP retrieves the latest reputation data for an IP
	// returns (result, exists, error)
	GetIP(ctx context.Context, ip string) (*models.EnhancedCachedResult, bool, error)

	// GetAllIPs retrieves all stored IP results
	GetAllIPs(ctx context.Context) ([]models.EnhancedCachedResult, error)

	// Close closes the underlying storage connection
	Close() error
}
