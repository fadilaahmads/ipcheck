package repositories

import (
	"context"
	"fmt"
	"sync"
	"time"

	"ipcheck/internal/models"
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

// SaveIP saves or updates the reputation data for a single IP.
// It uses an UPSERT (ON CONFLICT) strategy for the main reputation table
// and records a new entry in the scan history.
func (r *PostgresRepository) SaveIP(ctx context.Context, result *models.EnhancedCachedResult) error {
	// 1. Upsert into ip_reputation table
	const upsertReputation = `
		INSERT INTO ip_reputation (
			ip, risk_level, should_block, vt_malicious_count, vt_suspicious_count,
			vt_malicious_by, vt_suspicious_by,
			abuse_score, abuse_total_reports, is_tor, country_code, isp, 
			usage_type, domain, is_whitelisted, vt_last_queried, abuse_last_queried,
			last_updated_at, raw_vt_data, raw_abuse_data
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 
			$16, $17, CURRENT_TIMESTAMP, $18, $19
		)
		ON CONFLICT (ip) DO UPDATE SET
			risk_level = EXCLUDED.risk_level,
			should_block = EXCLUDED.should_block,
			vt_malicious_count = EXCLUDED.vt_malicious_count,
			vt_suspicious_count = EXCLUDED.vt_suspicious_count,
			vt_malicious_by = EXCLUDED.vt_malicious_by,
			vt_suspicious_by = EXCLUDED.vt_suspicious_by,
			abuse_score = EXCLUDED.abuse_score,
			abuse_total_reports = EXCLUDED.abuse_total_reports,
			is_tor = EXCLUDED.is_tor,
			country_code = EXCLUDED.country_code,
			isp = EXCLUDED.isp,
			usage_type = EXCLUDED.usage_type,
			domain = EXCLUDED.domain,
			is_whitelisted = EXCLUDED.is_whitelisted,
			vt_last_queried = EXCLUDED.vt_last_queried,
			abuse_last_queried = EXCLUDED.abuse_last_queried,
			last_updated_at = CURRENT_TIMESTAMP,
			raw_vt_data = EXCLUDED.raw_vt_data,
			raw_abuse_data = EXCLUDED.raw_abuse_data;
	`

	// Prepare time values for SQL
	vtLastQueried := time.Unix(result.VTLastQueried, 0)
	abuseLastQueried := time.Unix(result.AbuseLastQueried, 0)

	_, err := r.pool.Exec(ctx, upsertReputation,
		result.IP, result.RiskLevel, result.ShouldBlock, 
		len(result.VTMaliciousBy), len(result.VTSuspiciousBy),
		result.VTMaliciousBy, result.VTSuspiciousBy,
		result.AbuseScore, result.AbuseTotalReports, result.AbuseIsTor,
		result.AbuseCountry, result.AbuseISP, result.AbuseUsageType,
		result.AbuseDomain, result.IsWhitelisted,
		vtLastQueried, abuseLastQueried,
		result.VTRaw, result.AbuseRaw,
	)
	if err != nil {
		return fmt.Errorf("failed to upsert ip_reputation: %w", err)
	}

	// 2. Record in scan_history
	const insertHistory = `
		INSERT INTO scan_history (
			ip, risk_level, vt_malicious, abuse_score, triggered_by
		) VALUES ($1, $2, $3, $4, 'cli');
	`
	_, err = r.pool.Exec(ctx, insertHistory,
		result.IP, result.RiskLevel, len(result.VTMaliciousBy), result.AbuseScore,
	)
	if err != nil {
		return fmt.Errorf("failed to record scan_history: %w", err)
	}

	return nil
}

// GetIP retrieves the latest reputation data for an IP.
func (r *PostgresRepository) GetIP(ctx context.Context, ip string) (*models.EnhancedCachedResult, bool, error) {
	const query = `
		SELECT 
			ip, risk_level, should_block, vt_malicious_count, vt_suspicious_count,
			vt_malicious_by, vt_suspicious_by,
			abuse_score, abuse_total_reports, is_tor, country_code, isp, 
			usage_type, domain, is_whitelisted, vt_last_queried, abuse_last_queried,
			last_updated_at, raw_vt_data, raw_abuse_data
		FROM ip_reputation
		WHERE ip = $1;
	`

	var res models.EnhancedCachedResult
	var vtTime, abuseTime, updateTime time.Time
	var vtCount, suspCount int // temporary holders for counts if needed, but we use slices

	err := r.pool.QueryRow(ctx, query, ip).Scan(
		&res.IP, &res.RiskLevel, &res.ShouldBlock, &vtCount, &suspCount,
		&res.VTMaliciousBy, &res.VTSuspiciousBy,
		&res.AbuseScore, &res.AbuseTotalReports, &res.AbuseIsTor,
		&res.AbuseCountry, &res.AbuseISP, &res.AbuseUsageType,
		&res.AbuseDomain, &res.IsWhitelisted,
		&vtTime, &abuseTime, &updateTime,
		&res.VTRaw, &res.AbuseRaw,
	)

	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to get ip_reputation: %w", err)
	}

	// Convert times back to Unix int64
	res.VTLastQueried = vtTime.Unix()
	res.AbuseLastQueried = abuseTime.Unix()
	res.LastUpdated = updateTime.Unix()

	return &res, true, nil
}

// GetAllIPs retrieves all stored IP reputation data from the repository.
func (r *PostgresRepository) GetAllIPs(ctx context.Context) ([]models.EnhancedCachedResult, error) {
	const query = `
		SELECT 
			ip, risk_level, should_block, vt_malicious_count, vt_suspicious_count,
			vt_malicious_by, vt_suspicious_by,
			abuse_score, abuse_total_reports, is_tor, country_code, isp, 
			usage_type, domain, is_whitelisted, vt_last_queried, abuse_last_queried,
			last_updated_at, raw_vt_data, raw_abuse_data
		FROM ip_reputation;
	`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all IPs: %w", err)
	}
	defer rows.Close()

	var results []models.EnhancedCachedResult
	for rows.Next() {
		var res models.EnhancedCachedResult
		var vtTime, abuseTime, updateTime time.Time
		var vtCount, suspCount int

		err := rows.Scan(
			&res.IP, &res.RiskLevel, &res.ShouldBlock, &vtCount, &suspCount,
			&res.VTMaliciousBy, &res.VTSuspiciousBy,
			&res.AbuseScore, &res.AbuseTotalReports, &res.AbuseIsTor,
			&res.AbuseCountry, &res.AbuseISP, &res.AbuseUsageType,
			&res.AbuseDomain, &res.IsWhitelisted,
			&vtTime, &abuseTime, &updateTime,
			&res.VTRaw, &res.AbuseRaw,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan ip row: %w", err)
		}

		res.VTLastQueried = vtTime.Unix()
		res.AbuseLastQueried = abuseTime.Unix()
		res.LastUpdated = updateTime.Unix()

		results = append(results, res)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error during row iteration: %w", err)
	}

	return results, nil
}

// Close gracefully closes the database connection pool
func (r *PostgresRepository) Close() error {
	r.pool.Close()
	return nil
}
