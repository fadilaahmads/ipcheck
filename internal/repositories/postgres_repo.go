package repositories

import (
	"context"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresRepository implements the Repository interface using PostgreSQL
type PostgresRepository struct {
	pool *pgxpool.Pool
	mu   sync.RWMutex
}

// NewPostgresRepository creates a new PostgreSQL-based repository using connection pooling
func NewPostgresRepository(ctx context.Context, connStr string) (*PostgresRepository, error) {
	// Configure the connection pool
	config, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Create the pool
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Verify the connection is working
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &PostgresRepository{
		pool: pool,
	}, nil
}

// Close gracefully closes the database connection pool
func (r *PostgresRepository) Close() error {
	r.pool.Close()
	return nil
}
