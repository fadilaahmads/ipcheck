package repositories

import (
	"context"
	"fmt"
	"sync"

	"ipcheck/internal/cache"
	"ipcheck/internal/models"
)

// JSONRepository implements the Repository interface using a local JSON file
type JSONRepository struct {
	filePath string
	data     cache.CacheMap
	mu       sync.RWMutex
}

// NewJSONRepository creates a new JSON-based repository
func NewJSONRepository(path string) (*JSONRepository, error) {
	data, err := cache.LoadCache(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load JSON repository: %w", err)
	}

	return &JSONRepository{
		filePath: path,
		data:     data,
	}, nil
}

// SaveIP saves or updates the reputation data for a single IP in the JSON map
func (r *JSONRepository) SaveIP(ctx context.Context, result *models.EnhancedCachedResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	r.data[result.IP] = *result
	return nil
}

// GetIP retrieves the latest reputation data for an IP from the JSON map
func (r *JSONRepository) GetIP(ctx context.Context, ip string) (*models.EnhancedCachedResult, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result, exists := r.data[ip]
	if !exists {
		return nil, false, nil
	}
	
	// Create a copy to prevent external mutation of the cache map
	resCopy := result
	return &resCopy, true, nil
}

// GetAllIPs returns all results currently in the JSON map
func (r *JSONRepository) GetAllIPs(ctx context.Context) ([]models.EnhancedCachedResult, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make([]models.EnhancedCachedResult, 0, len(r.data))
	for _, res := range r.data {
		results = append(results, res)
	}
	return results, nil
}

// Close saves the JSON map back to the disk
func (r *JSONRepository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cache.SaveCache(r.filePath, r.data)
}
