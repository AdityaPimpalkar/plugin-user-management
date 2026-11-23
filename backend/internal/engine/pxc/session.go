package pxc

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

const (
	connectTimeout = 10 * time.Second
	// lockWaitTimeout bounds how long DDL waits for the metadata locks of
	// running transactions, e.g. DROP DATABASE, so it fails and is retried
	// instead of blocking the plugin.
	lockWaitTimeout = "10"

	errNoSuchTable = 1146
)

type stmt struct {
	sql  string
	args []any
}

// mysqlAccount is a user, by name, as it is in mysql.user.
type mysqlAccount struct {
	name string
	// anyHost tells the user has the 'user'@'%' account the plugin manages.
	anyHost bool
	// process and replClient are the global privileges of 'user'@'%'.
	process    bool
	replClient bool
}

// snapshot is what the plugin needs to know about the server, read at once.
type snapshot struct {
	accounts map[string]*mysqlAccount
	// grants are the database privileges of 'user'@'%', by user then by
	// mysql.db pattern, as sorted mysql.db columns.
	grants map[string]map[string][]string
	// allPrivileges are the privilege columns of mysql.db, sorted.
	allPrivileges []string
	schemas       []string
	// managedUsers keeps the password fingerprint of each managed user.
	managedUsers map[string]string
	// managedDatabases keeps the owner of each managed database.
	managedDatabases map[string]string
}

func (s *snapshot) hasSchema(name string) bool {
	return slices.Contains(s.schemas, name)
}

// owned returns the managed databases the user owns.
func (s *snapshot) owned(username string) map[string]bool {
	owned := map[string]bool{}
	for database, owner := range s.managedDatabases {
		if owner == username {
			owned[database] = true
		}
	}
	return owned
}

type session interface {
	// ensureCatalog creates the plugin's catalog when it's missing.
	ensureCatalog(ctx context.Context) error
	snapshot(ctx context.Context) (*snapshot, error)
	// exec runs the statements one by one; MySQL commits DDL on its own.
	exec(ctx context.Context, stmts []stmt) error
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
	cfg.ReadTimeout = 2 * connectTimeout
	cfg.WriteTimeout = connectTimeout
	// Proxies route prepared statements poorly; the driver escapes
	// arguments itself instead.
	cfg.InterpolateParams = true
	cfg.Params = map[string]string{"lock_wait_timeout": lockWaitTimeout}
	if c.tls {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(c.caPEM) {
			return nil, errors.New("invalid Percona XtraDB Cluster CA certificate")
		}
		cfg.TLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: c.serverName()}
	}
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure Percona XtraDB Cluster connection: %w", err)
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(2)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to Percona XtraDB Cluster: %w", err)
	}
	return &driverSession{db: db}, nil
}

func (s *driverSession) close() {
	_ = s.db.Close()
}

func (s *driverSession) exec(ctx context.Context, stmts []stmt) error {
	for _, st := range stmts {
		if _, err := s.db.ExecContext(ctx, st.sql, st.args...); err != nil {
			return err
		}
	}
	return nil
}

// ensureCatalog checks for the tables first: DDL, even IF NOT EXISTS, takes
// a cluster-wide lock on Galera.
func (s *driverSession) ensureCatalog(ctx context.Context) error {
	var count int
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME IN (?, ?)",
		catalogDatabase, usersTable, databasesTable).Scan(&count)
	if err != nil {
		return fmt.Errorf("check the plugin's catalog: %w", err)
	}
	if count == 2 {
		return nil
	}
	err = s.exec(ctx, []stmt{
		{sql: "CREATE DATABASE IF NOT EXISTS " + quoteIdent(catalogDatabase)},
		{sql: "CREATE TABLE IF NOT EXISTS " + catalogTable(usersTable) + ` (
  name VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL PRIMARY KEY,
  password_fingerprint VARCHAR(255) NOT NULL DEFAULT ''
) ENGINE=InnoDB`},
		{sql: "CREATE TABLE IF NOT EXISTS " + catalogTable(databasesTable) + ` (
  name VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL PRIMARY KEY,
  owner VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL
) ENGINE=InnoDB`},
	})
	if err != nil {
		return fmt.Errorf("create the plugin's catalog: %w", err)
	}
	return nil
}

func catalogTable(table string) string {
	return quoteIdent(catalogDatabase) + "." + quoteIdent(table)
}

func (s *driverSession) snapshot(ctx context.Context) (*snapshot, error) {
	snap := &snapshot{
		accounts:         map[string]*mysqlAccount{},
		grants:           map[string]map[string][]string{},
		managedUsers:     map[string]string{},
		managedDatabases: map[string]string{},
	}
	if err := s.readAccounts(ctx, snap); err != nil {
		return nil, err
	}
	if err := s.readGrants(ctx, snap); err != nil {
		return nil, err
	}
	schemas, err := s.strings(ctx, "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA")
	if err != nil {
		return nil, fmt.Errorf("list databases: %w", err)
	}
	snap.schemas = schemas
	if !snap.hasSchema(catalogDatabase) {
		return snap, nil
	}
	if err := s.readPairs(ctx, "SELECT name, password_fingerprint FROM "+catalogTable(usersTable), snap.managedUsers); err != nil {
		return nil, fmt.Errorf("read managed users: %w", err)
	}
	if err := s.readPairs(ctx, "SELECT name, owner FROM "+catalogTable(databasesTable), snap.managedDatabases); err != nil {
		return nil, fmt.Errorf("read managed databases: %w", err)
	}
	return snap, nil
}

func (s *driverSession) readAccounts(ctx context.Context, snap *snapshot) error {
	rows, err := s.db.QueryContext(ctx, "SELECT User, Host, Process_priv, Repl_client_priv FROM mysql.user")
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var user, host, process, replClient string
		if err := rows.Scan(&user, &host, &process, &replClient); err != nil {
			return fmt.Errorf("scan user: %w", err)
		}
		if user == "" {
			continue
		}
		a := snap.accounts[user]
		if a == nil {
			a = &mysqlAccount{name: user}
			snap.accounts[user] = a
		}
		if host == "%" {
			a.anyHost = true
			a.process = process == "Y"
			a.replClient = replClient == "Y"
		}
	}
	return rows.Err()
}

// readGrants reads mysql.db with all its columns: the privilege columns
// differ between MySQL versions.
func (s *driverSession) readGrants(ctx context.Context, snap *snapshot) error {
	rows, err := s.db.QueryContext(ctx, "SELECT * FROM mysql.db WHERE Host = '%'")
	if err != nil {
		return fmt.Errorf("list database grants: %w", err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return err
	}
	for _, column := range columns {
		if strings.HasSuffix(column, "_priv") {
			snap.allPrivileges = append(snap.allPrivileges, column)
		}
	}
	slices.Sort(snap.allPrivileges)
	values := make([]sql.RawBytes, len(columns))
	ptrs := make([]any, len(columns))
	for i := range values {
		ptrs[i] = &values[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return fmt.Errorf("scan database grant: %w", err)
		}
		var user, pattern string
		var privs []string
		for i, column := range columns {
			switch {
			case column == "User":
				user = string(values[i])
			case column == "Db":
				pattern = string(values[i])
			case strings.HasSuffix(column, "_priv") && string(values[i]) == "Y":
				privs = append(privs, column)
			}
		}
		if user == "" || len(privs) == 0 {
			continue
		}
		slices.Sort(privs)
		if snap.grants[user] == nil {
			snap.grants[user] = map[string][]string{}
		}
		snap.grants[user][pattern] = privs
	}
	return rows.Err()
}

func (s *driverSession) strings(ctx context.Context, query string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *driverSession) readPairs(ctx context.Context, query string, into map[string]string) error {
	rows, err := s.db.QueryContext(ctx, query)
	var me *mysql.MySQLError
	if errors.As(err, &me) && me.Number == errNoSuchTable {
		return nil
	}
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		into[k] = v
	}
	return rows.Err()
}

// serverReason returns the message of an error MySQL reported, or "" for
// other errors, such as a lost connection, which are worth retrying.
func serverReason(err error) string {
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		return me.Message
	}
	return ""
}

const (
	fingerprintScheme     = "pbkdf2-sha256"
	fingerprintIterations = 4096
)

// fingerprint returns a salted hash of the password, kept in the catalog to
// tell when the password Secret changes: MySQL's own hashes can't be
// checked without logging in.
func fingerprint(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return fingerprintWith(password, salt, fingerprintIterations)
}

func fingerprintWith(password string, salt []byte, iterations int) (string, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{fingerprintScheme, strconv.Itoa(iterations), hex.EncodeToString(salt), hex.EncodeToString(key)}, "$"), nil
}

func fingerprintMatches(stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != fingerprintScheme {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 || iterations > 1_000_000 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := fingerprintWith(password, salt, iterations)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(stored)) == 1
}
