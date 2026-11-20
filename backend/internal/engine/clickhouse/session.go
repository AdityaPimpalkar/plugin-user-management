package clickhouse

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const connectTimeout = 10 * time.Second

type databaseUser struct {
	name    string
	storage string
}

type databaseGrant struct {
	username    string
	accessType  string
	database    string
	table       string
	grantOption bool
}

type databaseRecord struct {
	name    string
	comment string
}

type session interface {
	users(context.Context) ([]databaseUser, error)
	roleMembers(context.Context) (map[string]bool, error)
	grants(context.Context) ([]databaseGrant, error)
	databases(context.Context) ([]databaseRecord, error)
	exec(context.Context, string) error
	close() error
}

type dialer func(context.Context, cluster) (session, error)

type driverSession struct {
	conn driver.Conn
}

func dialDriver(ctx context.Context, c cluster) (session, error) {
	options := &clickhouse.Options{
		Protocol: clickhouse.Native,
		Addr:     []string{c.host + ":" + strconv.Itoa(c.port)},
		Auth: clickhouse.Auth{
			Database: defaultDatabase,
			Username: c.adminUser,
			Password: c.adminPass,
		},
		DialTimeout:  connectTimeout,
		ReadTimeout:  connectTimeout,
		MaxOpenConns: 1,
		MaxIdleConns: 1,
	}
	if c.tls {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(c.caPEM) {
			return nil, errors.New("invalid ClickHouse CA certificate")
		}
		options.TLS = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		}
	}
	conn, err := clickhouse.Open(options)
	if err != nil {
		return nil, fmt.Errorf("configure ClickHouse connection: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("connect to ClickHouse: %w", err)
	}
	return &driverSession{conn: conn}, nil
}

func (s *driverSession) users(ctx context.Context) ([]databaseUser, error) {
	rows, err := s.conn.Query(ctx, "SELECT name, storage FROM system.users ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("list ClickHouse users: %w", err)
	}
	defer rows.Close()

	var users []databaseUser
	for rows.Next() {
		var user databaseUser
		if err := rows.Scan(&user.name, &user.storage); err != nil {
			return nil, fmt.Errorf("scan ClickHouse user: %w", err)
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *driverSession) roleMembers(ctx context.Context) (map[string]bool, error) {
	rows, err := s.conn.Query(ctx,
		"SELECT ifNull(user_name, '') FROM system.role_grants "+
			"WHERE user_name IS NOT NULL AND granted_role_name = ?",
		managedRole)
	if err != nil {
		return nil, fmt.Errorf("list ClickHouse managed users: %w", err)
	}
	defer rows.Close()

	users := map[string]bool{}
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return nil, fmt.Errorf("scan ClickHouse role membership: %w", err)
		}
		users[username] = true
	}
	return users, rows.Err()
}

func (s *driverSession) grants(ctx context.Context) ([]databaseGrant, error) {
	rows, err := s.conn.Query(ctx,
		"SELECT ifNull(user_name, ''), toString(access_type), "+
			"ifNull(database, ''), ifNull(table, ''), grant_option "+
			"FROM system.grants "+
			"WHERE user_name IS NOT NULL AND is_partial_revoke = 0")
	if err != nil {
		return nil, fmt.Errorf("list ClickHouse grants: %w", err)
	}
	defer rows.Close()

	var grants []databaseGrant
	for rows.Next() {
		var grant databaseGrant
		var grantOption uint8
		if err := rows.Scan(&grant.username, &grant.accessType, &grant.database, &grant.table, &grantOption); err != nil {
			return nil, fmt.Errorf("scan ClickHouse grant: %w", err)
		}
		grant.grantOption = grantOption != 0
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (s *driverSession) databases(ctx context.Context) ([]databaseRecord, error) {
	rows, err := s.conn.Query(ctx, "SELECT name, comment FROM system.databases ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("list ClickHouse databases: %w", err)
	}
	defer rows.Close()

	var databases []databaseRecord
	for rows.Next() {
		var database databaseRecord
		if err := rows.Scan(&database.name, &database.comment); err != nil {
			return nil, fmt.Errorf("scan ClickHouse database: %w", err)
		}
		databases = append(databases, database)
	}
	return databases, rows.Err()
}

func (s *driverSession) exec(ctx context.Context, query string) error {
	if err := s.conn.Exec(ctx, query); err != nil {
		return fmt.Errorf("execute ClickHouse query: %w", err)
	}
	return nil
}

func (s *driverSession) close() error {
	return s.conn.Close()
}
