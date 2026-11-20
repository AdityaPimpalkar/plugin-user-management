package clickhouse

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openeverest/plugin-user-management/backend/internal/engine"
)

type fakeSession struct {
	mu sync.Mutex

	usersValue     []databaseUser
	membersValue   map[string]bool
	grantsValue    []databaseGrant
	databasesValue []databaseRecord
	queries        []string

	active  atomic.Int32
	overlap atomic.Bool
	delay   time.Duration
}

func (s *fakeSession) enter() func() {
	if s.active.Add(1) > 1 {
		s.overlap.Store(true)
	}
	return func() {
		if s.delay > 0 {
			time.Sleep(s.delay)
		}
		s.active.Add(-1)
	}
}

func (s *fakeSession) users(context.Context) ([]databaseUser, error) {
	done := s.enter()
	defer done()
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.usersValue), nil
}

func (s *fakeSession) roleMembers(context.Context) (map[string]bool, error) {
	done := s.enter()
	defer done()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]bool{}
	for name, managed := range s.membersValue {
		out[name] = managed
	}
	return out, nil
}

func (s *fakeSession) grants(context.Context) ([]databaseGrant, error) {
	done := s.enter()
	defer done()
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.grantsValue), nil
}

func (s *fakeSession) databases(context.Context) ([]databaseRecord, error) {
	done := s.enter()
	defer done()
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.databasesValue), nil
}

func (s *fakeSession) exec(_ context.Context, query string) error {
	done := s.enter()
	defer done()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, query)
	return nil
}

func (s *fakeSession) close() error {
	return nil
}

func testEngine(s *fakeSession) *Engine {
	return &Engine{
		resolve: func(context.Context, engine.Target) (cluster, error) {
			return cluster{name: "events", namespace: "team-a", distributed: true}, nil
		},
		dial: func(context.Context, cluster) (session, error) { return s, nil },
		readPassword: func(context.Context, string, engine.SecretKeyRef) (string, string, error) {
			return "correct-horse-battery-staple", "", nil
		},
		locks: map[string]*sync.Mutex{},
	}
}

func TestSyncUsersDoesNotTakeOverExistingAccount(t *testing.T) {
	s := &fakeSession{usersValue: []databaseUser{{name: "app"}}, membersValue: map[string]bool{}}
	e := testEngine(s)
	target := engine.Target{Namespace: "team-a", Instance: "events"}

	err := e.SyncUsers(context.Background(), target, []engine.DesiredUser{{
		Username: "app",
		Password: engine.SecretKeyRef{Name: "app-password", Key: "password"},
	}})
	require.NoError(t, err)
	assert.Contains(t, e.UserProblem(target, "app"), "isn't managed by OpenEverest")
	assert.Len(t, s.queries, 1, "only the marker role may be ensured")
}

func TestDropUserRefusesDatabaseOwner(t *testing.T) {
	s := &fakeSession{
		membersValue: map[string]bool{"owner": true},
		databasesValue: []databaseRecord{{
			name: "orders", comment: managedDatabaseComment("owner"),
		}},
	}
	e := testEngine(s)
	err := e.DropUser(context.Background(), engine.Target{Namespace: "team-a", Instance: "events"}, "owner")
	assert.ErrorIs(t, err, engine.ErrInProgress)
	assert.Empty(t, s.queries)
}

func TestConcurrentUserAndDatabaseOperationsAreSerialized(t *testing.T) {
	s := &fakeSession{
		delay:          time.Millisecond,
		usersValue:     []databaseUser{{name: "owner"}},
		membersValue:   map[string]bool{"owner": true},
		databasesValue: []databaseRecord{{name: "orders", comment: managedDatabaseComment("owner")}},
	}
	e := testEngine(s)
	target := engine.Target{Namespace: "team-a", Instance: "events"}

	const operations = 20
	errs := make(chan error, operations)
	var wg sync.WaitGroup
	for i := 0; i < operations; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				errs <- e.SyncUsers(context.Background(), target, []engine.DesiredUser{{
					Username: "owner",
					Roles:    []engine.RoleGrant{{Role: roleRead, Database: "orders"}},
					Password: engine.SecretKeyRef{Name: "owner-password", Key: "password"},
				}})
				return
			}
			errs <- e.SyncDatabase(context.Background(), target, engine.DesiredDatabase{
				Name: "orders", Owner: "owner",
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.False(t, s.overlap.Load(), "ClickHouse writes for one installation must not overlap")
}

func TestConcurrentLockMapIsSafeForDifferentTargets(t *testing.T) {
	s := &fakeSession{delay: time.Microsecond}
	e := testEngine(s)

	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := engine.Target{Namespace: "team-a", Instance: "db-" + string(rune('a'+i%5))}
			errs <- e.SyncUsers(context.Background(), target, []engine.DesiredUser{{
				Username: "app",
				Password: engine.SecretKeyRef{Name: "password", Key: "password"},
			}})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.True(t, err == nil || errors.Is(err, engine.ErrInvalid), err)
	}
}
