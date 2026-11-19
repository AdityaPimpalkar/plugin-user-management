package mariadb

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
)

const connectTimeout = 10 * time.Second

var (
	registeredTLS   = map[string]bool{}
	registeredTLSMu sync.Mutex
)

type databaseUser struct {
	name string
	host string
}

type databaseSchema struct {
	name string
}

type session interface {
	users(context.Context) ([]databaseUser, error)
	databases(context.Context) ([]databaseSchema, error)
	close()
}

type dialer func(context.Context, cluster) (session, error)

type driverSession struct {
	db *sql.DB
}

func dialDriver(ctx context.Context, c cluster) (session, error) {
	cfg := mysql.NewConfig()
	cfg.User = "root"
	cfg.Passwd = c.rootPassword
	cfg.Net = "tcp"
	cfg.Addr = fmt.Sprintf("%s:%d", c.host, c.port)
	cfg.Timeout = connectTimeout
	cfg.ReadTimeout = connectTimeout
	cfg.WriteTimeout = connectTimeout
	if c.tlsEnabled {
		tlsName, err := tlsConfigName(c.caPEM)
		if err != nil {
			return nil, err
		}
		cfg.TLSConfig = tlsName
	}
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure MariaDB connection: %w", err)
	}
	db := sql.OpenDB(conn)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to MariaDB: %w", err)
	}
	return &driverSession{db: db}, nil
}

func tlsConfigName(caPEM []byte) (string, error) {
	sum := sha256.Sum256(caPEM)
	name := "openeverest-user-management-" + hex.EncodeToString(sum[:8])
	registeredTLSMu.Lock()
	defer registeredTLSMu.Unlock()
	if registeredTLS[name] {
		return name, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return "", errors.New("invalid MariaDB CA certificate")
	}
	if err := mysql.RegisterTLSConfig(name, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}); err != nil {
		return "", fmt.Errorf("register MariaDB TLS configuration: %w", err)
	}
	registeredTLS[name] = true
	return name, nil
}

func (s *driverSession) users(ctx context.Context) ([]databaseUser, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT User, Host FROM mysql.user")
	if err != nil {
		return nil, fmt.Errorf("list MariaDB users: %w", err)
	}
	defer rows.Close()
	var users []databaseUser
	for rows.Next() {
		var user databaseUser
		if err := rows.Scan(&user.name, &user.host); err != nil {
			return nil, fmt.Errorf("scan MariaDB user: %w", err)
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *driverSession) databases(ctx context.Context) ([]databaseSchema, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA")
	if err != nil {
		return nil, fmt.Errorf("list MariaDB databases: %w", err)
	}
	defer rows.Close()
	var databases []databaseSchema
	for rows.Next() {
		var database databaseSchema
		if err := rows.Scan(&database.name); err != nil {
			return nil, fmt.Errorf("scan MariaDB database: %w", err)
		}
		databases = append(databases, database)
	}
	return databases, rows.Err()
}

func (s *driverSession) close() {
	_ = s.db.Close()
}
