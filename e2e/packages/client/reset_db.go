package client

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ServicePortProvider provides a way to get the mapped port for a service
type ServicePortProvider interface {
	GetServicePort(ctx context.Context, serviceName string, internalPort string) (string, error)
}

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	User     string
	Password string
	Database string
	Host     string
	Port     string
}

// DefaultDatabaseConfig returns the default database configuration
func DefaultDatabaseConfig() DatabaseConfig {
	return DatabaseConfig{
		User:     "infisical",
		Password: "infisical",
		Database: "infisical",
		Host:     "localhost",
		Port:     "5432",
	}
}

// ResetDBOptions holds options for resetting the database
type ResetDBOptions struct {
	SkipTables map[string]struct{} // Tables to skip when truncating (e.g., migrations)
	DBConfig   DatabaseConfig
}

// DefaultResetDBOptions returns default options for resetting the database
func DefaultResetDBOptions() ResetDBOptions {
	return ResetDBOptions{
		SkipTables: map[string]struct{}{
			"public.infisical_migrations":      {},
			"public.infisical_migrations_lock": {},
		},
		DBConfig: DefaultDatabaseConfig(),
	}
}

// ResetDB resets the PostgreSQL database.
// It accepts a port provider to get service ports, and options to configure the reset behavior.
func ResetDB(ctx context.Context, opts ...func(*ResetDBOptions)) error {
	options := DefaultResetDBOptions()
	for _, opt := range opts {
		opt(&options)
	}

	// Reset PostgreSQL database
	if err := resetPostgresDB(ctx, options); err != nil {
		return fmt.Errorf("failed to reset PostgreSQL database: %w", err)
	}

	return nil
}

// resetPostgresDB resets the PostgreSQL database by truncating all tables (except skipped ones)
// and inserting a default super_admin record.
func resetPostgresDB(ctx context.Context, opts ResetDBOptions) error {
	slog.Info("Resetting Postgres database")

	// Build connection string using config
	connStr := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s",
		opts.DBConfig.User,
		opts.DBConfig.Password,
		opts.DBConfig.Host,
		opts.DBConfig.Port,
		opts.DBConfig.Database,
	)

	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		slog.Error("Unable to connect to database", "err", err)
		return err
	}
	defer conn.Close(ctx)

	// Get all tables
	query := `
		SELECT table_schema, table_name
		FROM information_schema.tables
		WHERE table_type = 'BASE TABLE'
		  AND table_schema NOT IN ('pg_catalog', 'information_schema')
		ORDER BY table_schema, table_name;
	`

	rows, err := conn.Query(ctx, query)
	if err != nil {
		slog.Error("Unable to execute query", "query", query, "err", err)
		return err
	}
	defer rows.Close()

	tables := make([]string, 0)
	for rows.Next() {
		var schema, table string
		if err := rows.Scan(&schema, &table); err != nil {
			slog.Error("Scan failed", "error", err)
			return err
		}
		tables = append(tables, fmt.Sprintf("%s.%s", schema, table))
	}
	if err := rows.Err(); err != nil {
		slog.Error("Row iteration error", "error", err)
		return err
	}

	// Build truncate statement with all tables
	tablesToTruncate := make([]string, 0)
	for _, table := range tables {
		if _, ok := opts.SkipTables[table]; ok {
			continue
		}
		tablesToTruncate = append(tablesToTruncate, table)
	}

	if len(tablesToTruncate) > 0 {
		truncateQuery := fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE;", strings.Join(tablesToTruncate, ", "))
		_, err = conn.Exec(ctx, truncateQuery)
		if err != nil {
			slog.Error("Truncate failed", "error", err)
			return err
		}
		slog.Info("Truncate all tables successfully")
	}

	// Insert default super_admin record
	_, err = conn.Exec(ctx,
		`INSERT INTO public.super_admin ("id", "fipsEnabled", "initialized", "allowSignUp") VALUES ($1, $2, $3, $4)`,
		"00000000-0000-0000-0000-000000000000", true, false, true)
	if err != nil {
		slog.Error("Failed to insert super_admin", "error", err)
		return err
	}

	return nil
}

// WithSkipTables sets the tables to skip when truncating
func WithSkipTables(tables map[string]struct{}) func(*ResetDBOptions) {
	return func(opts *ResetDBOptions) {
		opts.SkipTables = tables
	}
}

// WithDatabaseConfig sets the database configuration
func WithDatabaseConfig(config DatabaseConfig) func(*ResetDBOptions) {
	return func(opts *ResetDBOptions) {
		opts.DBConfig = config
	}
}
