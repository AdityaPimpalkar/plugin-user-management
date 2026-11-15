package mssql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	mssqldb "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

const (
	connectTimeout  = 10 * time.Second
	lockTimeoutMS   = 10000
	applicationName = "openeverest-plugin-user-management"
	// agDatabasesLock is the application lock the operator holds while it
	// adds a database to the Availability Group; holding it across REMOVE
	// DATABASE and DROP DATABASE keeps the operator from adding the database
	// back in between.
	agDatabasesLock = "mssql-operator/ag-databases"
	// SQL Server's error when KILL names a session that already ended.
	errNotActiveProcess = 6106
)

// Every login, with whether the plugin manages it and its server permissions.
const loginsQuery = `
SELECT sp.name, sp.sid, sp.type,
       CASE WHEN EXISTS (SELECT 1 FROM sys.server_role_members rm
                         JOIN sys.server_principals r ON r.principal_id = rm.role_principal_id
                         WHERE rm.member_principal_id = sp.principal_id AND r.name = @marker)
            THEN 1 ELSE 0 END,
       ISNULL((SELECT STRING_AGG(p.permission_name, N',') FROM sys.server_permissions p
               WHERE p.grantee_principal_id = sp.principal_id AND p.class = 100 AND p.state = 'G'), N'')
FROM sys.server_principals sp
WHERE sp.type IN ('S', 'U', 'G', 'E', 'X', 'C', 'K')`

const passwordQuery = `SELECT PWDCOMPARE(@password, password_hash) FROM sys.sql_logins WHERE name = @name`

const databasesQuery = `
SELECT d.name, d.database_id, d.state_desc,
       CASE WHEN d.group_database_id IS NULL THEN 0 ELSE 1 END,
       ISNULL(SUSER_SNAME(d.owner_sid), N''),
       ISNULL(HAS_DBACCESS(d.name), 0)
FROM sys.databases d
ORDER BY d.name`

// The plugin's mark and the owner (dbo) of a database; %[1]s is the quoted database.
const databaseDetailsQuery = `
SELECT ISNULL(CAST((SELECT value FROM %[1]s.sys.extended_properties
                    WHERE class = 0 AND name = @marker) AS nvarchar(256)), N''),
       (SELECT sid FROM %[1]s.sys.database_principals WHERE principal_id = 1)`

// The SQL users of a database with the roles they are members of; %[1]s
// is the quoted database.
const databaseUsersQuery = `
SELECT u.name, u.sid, ISNULL(r.name, N'')
FROM %[1]s.sys.database_principals u
LEFT JOIN %[1]s.sys.database_role_members m ON m.member_principal_id = u.principal_id
LEFT JOIN %[1]s.sys.database_principals r ON r.principal_id = m.role_principal_id
WHERE u.type = 'S' AND u.principal_id > 4 AND u.sid IS NOT NULL`

const databaseSessionsQuery = `
SELECT session_id, status FROM sys.dm_exec_sessions
WHERE database_id = DB_ID(@name) AND session_id <> @@SPID AND is_user_process = 1`

const loginSessionsQuery = `
SELECT session_id FROM sys.dm_exec_sessions
WHERE login_name = @name AND session_id <> @@SPID AND is_user_process = 1`

const getAGLockQuery = `
DECLARE @r int;
EXEC @r = master.sys.sp_getapplock @Resource = @resource, @LockMode = 'Exclusive',
     @LockOwner = 'Session', @LockTimeout = @timeout, @DbPrincipal = 'public';
SELECT @r`

const releaseAGLockQuery = `EXEC master.sys.sp_releaseapplock @Resource = @resource, @LockOwner = 'Session', @DbPrincipal = 'public'`

// login is a server principal that logs in.
type login struct {
	name string
	sid  []byte
	// kind is sys.server_principals.type: S for SQL logins.
	kind    string
	managed bool
	// permissions are the server permissions granted to it.
	permissions []string
}

// dbUser is a SQL user of a database, mapped to the login with its SID.
type dbUser struct {
	name  string
	sid   []byte
	roles []string
}

// database is a database as sys.databases reports it, with details read
// in the database itself when it's online and accessible.
type database struct {
	name  string
	id    int
	state string
	inAG  bool
	// ownerName is the owner as this replica's sys.databases has it.
	ownerName string
	// detailed is set once marker, dboSID and users are read.
	detailed bool
	marker   string
	dboSID   []byte
	users    []dbUser
}

func (d database) system() bool {
	return d.id <= 4
}

func (d database) online() bool {
	return d.state == "ONLINE"
}

func (d database) managed() bool {
	return d.marker == managedValue
}

// userFor returns the user mapped to the login with the SID, or nil.
func (d database) userFor(sid []byte) *dbUser {
	for i := range d.users {
		if string(d.users[i].sid) == string(sid) {
			return &d.users[i]
		}
	}
	return nil
}

// stmt runs in the database, or in master when database is empty.
type stmt struct {
	database string
	sql      string
}

// session reads and changes the logins and databases of a SQL Server.
type session interface {
	logins(ctx context.Context) ([]login, error)
	// passwordMatches tells whether the SQL login has the password.
	passwordMatches(ctx context.Context, name, password string) (bool, error)
	databases(ctx context.Context) ([]database, error)
	// execTx runs the statements in one transaction.
	execTx(ctx context.Context, stmts []stmt) error
	// execEach runs the statements one by one, outside a transaction, as
	// CREATE DATABASE, DROP DATABASE and ALTER AVAILABILITY GROUP require.
	execEach(ctx context.Context, stmts []stmt) error
	// databaseSessions returns the user sessions using the database: the
	// idle ones, and how many others run requests.
	databaseSessions(ctx context.Context, name string) (idle []int64, busy int, err error)
	loginSessions(ctx context.Context, name string) ([]int64, error)
	// kill ends sessions; ended ones are skipped.
	kill(ctx context.Context, ids []int64) error
	// withAGLock runs fn holding the operator's lock on the Availability
	// Group's databases; ErrInProgress when the operator holds it.
	withAGLock(ctx context.Context, fn func() error) error
	close()
}

// dialer connects to the primary of the cluster.
type dialer func(ctx context.Context, c cluster) (session, error)

type sqlSession struct {
	db   *sql.DB
	conn *sql.Conn
}

// sqlDialer connects to the primary's master database as sa, over TLS
// verified against the instance's CA when the instance uses TLS.
func sqlDialer(kube kubernetes.Interface) dialer {
	return func(ctx context.Context, c cluster) (session, error) {
		secrets := kube.CoreV1().Secrets(c.namespace)
		creds, err := secrets.Get(ctx, c.saSecret, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("%w: sa password secret %q not found", engine.ErrNotReady, c.saSecret)
		}
		if err != nil {
			return nil, fmt.Errorf("get sa password secret %q: %w", c.saSecret, err)
		}
		password := string(creds.Data[saPassword])
		if password == "" {
			return nil, fmt.Errorf("sa password secret %q has no %s", c.saSecret, saPassword)
		}
		query := url.Values{
			"database":     {"master"},
			"app name":     {applicationName},
			"dial timeout": {strconv.Itoa(int(connectTimeout.Seconds()))},
		}
		if c.tls {
			query.Set("encrypt", "true")
		} else {
			// Only the login is encrypted, with the server's own certificate.
			query.Set("encrypt", "false")
			query.Set("TrustServerCertificate", "true")
		}
		dsn := url.URL{
			Scheme:   "sqlserver",
			User:     url.UserPassword("sa", password),
			Host:     net.JoinHostPort(c.host, strconv.FormatInt(c.port, 10)),
			RawQuery: query.Encode(),
		}
		cfg, err := msdsn.Parse(dsn.String())
		if err != nil {
			return nil, errors.New("SQL Server connection config is invalid")
		}
		if c.tls {
			tlsConfig, err := tlsConfigFor(ctx, kube, c)
			if err != nil {
				return nil, err
			}
			cfg.TLSConfig = tlsConfig
		}
		db := sql.OpenDB(mssqldb.NewConnectorConfig(cfg))
		dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
		defer cancel()
		conn, err := db.Conn(dialCtx)
		if err == nil {
			_, err = conn.ExecContext(dialCtx, fmt.Sprintf("SET LOCK_TIMEOUT %d", lockTimeoutMS))
		}
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			_ = db.Close()
			return nil, fmt.Errorf("connect to SQL Server: %w", err)
		}
		return &sqlSession{db: db, conn: conn}, nil
	}
}

// tlsConfigFor trusts the CA of the TLS Secret, or the system's roots for
// a certificate of the user's own without one.
func tlsConfigFor(ctx context.Context, kube kubernetes.Interface, c cluster) (*tls.Config, error) {
	serverName := c.tlsServerName
	if serverName == "" {
		serverName = c.host
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	secret, err := kube.CoreV1().Secrets(c.namespace).Get(ctx, c.tlsSecret, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("%w: TLS secret %q not found", engine.ErrNotReady, c.tlsSecret)
	}
	if err != nil {
		return nil, fmt.Errorf("get TLS secret %q: %w", c.tlsSecret, err)
	}
	if ca := secret.Data[caCertKey]; len(ca) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("TLS secret %q has no valid %s", c.tlsSecret, caCertKey)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func (s *sqlSession) logins(ctx context.Context) ([]login, error) {
	rows, err := s.conn.QueryContext(ctx, loginsQuery, sql.Named("marker", managedRole))
	if err != nil {
		return nil, fmt.Errorf("list logins: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []login
	for rows.Next() {
		var l login
		var managed int
		var permissions string
		if err := rows.Scan(&l.name, &l.sid, &l.kind, &managed, &permissions); err != nil {
			return nil, fmt.Errorf("list logins: %w", err)
		}
		l.kind = strings.TrimSpace(l.kind)
		l.managed = managed == 1
		if permissions != "" {
			l.permissions = strings.Split(permissions, ",")
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list logins: %w", err)
	}
	return out, nil
}

func (s *sqlSession) passwordMatches(ctx context.Context, name, password string) (bool, error) {
	var match sql.NullInt64
	err := s.conn.QueryRowContext(ctx, passwordQuery, sql.Named("password", password), sql.Named("name", name)).Scan(&match)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check password of login %q: %w", name, err)
	}
	return match.Valid && match.Int64 == 1, nil
}

func (s *sqlSession) databases(ctx context.Context) ([]database, error) {
	rows, err := s.conn.QueryContext(ctx, databasesQuery)
	if err != nil {
		return nil, fmt.Errorf("list databases: %w", err)
	}
	var out []database
	var access []bool
	for rows.Next() {
		var d database
		var inAG, hasAccess int
		if err := rows.Scan(&d.name, &d.id, &d.state, &inAG, &d.ownerName, &hasAccess); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("list databases: %w", err)
		}
		d.inAG = inAG == 1
		out = append(out, d)
		access = append(access, hasAccess == 1)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, fmt.Errorf("list databases: %w", err)
	}
	for i := range out {
		if out[i].system() || !out[i].online() || !access[i] {
			continue
		}
		if err := s.readDetails(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *sqlSession) readDetails(ctx context.Context, d *database) error {
	db := quoteName(d.name)
	err := s.conn.QueryRowContext(ctx, fmt.Sprintf(databaseDetailsQuery, db), sql.Named("marker", managedProperty)).Scan(&d.marker, &d.dboSID)
	if err != nil {
		return fmt.Errorf("read database %q: %w", d.name, err)
	}
	rows, err := s.conn.QueryContext(ctx, fmt.Sprintf(databaseUsersQuery, db))
	if err != nil {
		return fmt.Errorf("list users of database %q: %w", d.name, err)
	}
	defer func() { _ = rows.Close() }()
	index := map[string]int{}
	for rows.Next() {
		var name, role string
		var sid []byte
		if err := rows.Scan(&name, &sid, &role); err != nil {
			return fmt.Errorf("list users of database %q: %w", d.name, err)
		}
		i, ok := index[name]
		if !ok {
			i = len(d.users)
			index[name] = i
			d.users = append(d.users, dbUser{name: name, sid: sid})
		}
		if role != "" {
			d.users[i].roles = append(d.users[i].roles, role)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list users of database %q: %w", d.name, err)
	}
	d.detailed = true
	return nil
}

func (s *sqlSession) run(ctx context.Context, ex interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, st stmt,
) error {
	if st.database == "" {
		_, err := ex.ExecContext(ctx, st.sql)
		return err
	}
	_, err := ex.ExecContext(ctx, "EXEC "+quoteName(st.database)+".sys.sp_executesql @stmt", sql.Named("stmt", st.sql))
	return err
}

func (s *sqlSession) execTx(ctx context.Context, stmts []stmt) error {
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, st := range stmts {
		if err := s.run(ctx, tx, st); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *sqlSession) execEach(ctx context.Context, stmts []stmt) error {
	for _, st := range stmts {
		if err := s.run(ctx, s.conn, st); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqlSession) databaseSessions(ctx context.Context, name string) ([]int64, int, error) {
	rows, err := s.conn.QueryContext(ctx, databaseSessionsQuery, sql.Named("name", name))
	if err != nil {
		return nil, 0, fmt.Errorf("list sessions of database %q: %w", name, err)
	}
	defer func() { _ = rows.Close() }()
	var idle []int64
	busy := 0
	for rows.Next() {
		var id int64
		var status string
		if err := rows.Scan(&id, &status); err != nil {
			return nil, 0, fmt.Errorf("list sessions of database %q: %w", name, err)
		}
		if strings.EqualFold(strings.TrimSpace(status), "sleeping") {
			idle = append(idle, id)
		} else {
			busy++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list sessions of database %q: %w", name, err)
	}
	return idle, busy, nil
}

func (s *sqlSession) loginSessions(ctx context.Context, name string) ([]int64, error) {
	rows, err := s.conn.QueryContext(ctx, loginSessionsQuery, sql.Named("name", name))
	if err != nil {
		return nil, fmt.Errorf("list sessions of login %q: %w", name, err)
	}
	defer func() { _ = rows.Close() }()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("list sessions of login %q: %w", name, err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list sessions of login %q: %w", name, err)
	}
	return ids, nil
}

func (s *sqlSession) kill(ctx context.Context, ids []int64) error {
	for _, id := range ids {
		_, err := s.conn.ExecContext(ctx, "KILL "+strconv.FormatInt(id, 10))
		var serverErr mssqldb.Error
		if err != nil && !(errors.As(err, &serverErr) && serverErr.Number == errNotActiveProcess) {
			return err
		}
	}
	return nil
}

func (s *sqlSession) withAGLock(ctx context.Context, fn func() error) error {
	var result int
	err := s.conn.QueryRowContext(ctx, getAGLockQuery,
		sql.Named("resource", agDatabasesLock), sql.Named("timeout", lockTimeoutMS)).Scan(&result)
	if err != nil {
		return fmt.Errorf("lock the Availability Group's databases: %w", err)
	}
	if result < 0 {
		return fmt.Errorf("%w: the operator is changing the Availability Group's databases", engine.ErrInProgress)
	}
	defer func() {
		_, _ = s.conn.ExecContext(context.WithoutCancel(ctx), releaseAGLockQuery, sql.Named("resource", agDatabasesLock))
	}()
	return fn()
}

func (s *sqlSession) close() {
	_ = s.conn.Close()
	_ = s.db.Close()
}

// serverReason returns SQL Server's message for an error it raised, or ""
// for other errors, such as lost connections.
func serverReason(err error) string {
	var serverErr mssqldb.Error
	if errors.As(err, &serverErr) {
		return serverErr.Message
	}
	return ""
}
