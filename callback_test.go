package rediswatcher_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/casbin/redis-watcher/v2"
	"github.com/casbin/redis-watcher/v2/mocks"
	"github.com/go-redis/redis/v8"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
)

type testlogger struct {
}

func (l testlogger) Printf(ctx context.Context, format string, v ...interface{}) {
	fmt.Printf(format, v...)
}

func initSyncedWatcher(t *testing.T, id string, server *miniredis.Miniredis) (*casbin.SyncedEnforcer, *rediswatcher.Watcher, *mocks.MockBatchAdapter, *gomock.Controller) {
	logger := testlogger{}
	mockCtrl := gomock.NewController(t)
	adapter := mocks.NewMockBatchAdapter(mockCtrl)
	adapter.EXPECT().LoadPolicy(gomock.Any()).Return(nil).Times(1)

	e, err := casbin.NewSyncedEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	callback := rediswatcher.NewSyncedCallbackHandler(id, e, logger).Handle
	w, err := rediswatcher.NewWatcher(server.Addr(), rediswatcher.WatcherOptions{
		LocalID:                id,
		Hooks:                  []redis.Hook{rediswatcher.DefaultHook{}},
		OptionalUpdateCallback: callback,
	})
	if err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

	_ = e.SetWatcher(w)
	err = w.SetUpdateCallback(callback)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	return e, w.(*rediswatcher.Watcher), adapter, mockCtrl
}

func initSyncedWatcherUpdatable(t *testing.T, id string, server *miniredis.Miniredis) (*casbin.SyncedEnforcer, *rediswatcher.Watcher, *mocks.MockUpdatableAdapter, *gomock.Controller) {
	logger := testlogger{}
	mockCtrl := gomock.NewController(t)
	adapter := mocks.NewMockUpdatableAdapter(mockCtrl)
	adapter.EXPECT().LoadPolicy(gomock.Any()).Return(nil).Times(1)

	e, err := casbin.NewSyncedEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("Failed to create enforcer: %v", err)
	}

	callback := rediswatcher.NewSyncedCallbackHandler(id, e, logger).Handle
	w, err := rediswatcher.NewWatcher(server.Addr(), rediswatcher.WatcherOptions{
		LocalID:                id,
		Hooks:                  []redis.Hook{rediswatcher.DefaultHook{}},
		OptionalUpdateCallback: callback,
	})
	if err != nil {
		t.Fatalf("Failed to connect to Redis: %v", err)
	}

	_ = e.SetWatcher(w)
	err = w.SetUpdateCallback(callback)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	return e, w.(*rediswatcher.Watcher), adapter, mockCtrl
}

func assertResult(t *testing.T, response bool, err error) {
	if err != nil {
		t.Error(err)
	}
	if !response {
		t.Fatalf("response should be %v instead of %v", response, !response)
	}
}

func TestSyncedCallbackHandler_UpdateForAddPolicy(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create to Redis server: %v", err)
	}

	writer, watcher1, adapter, ctrl1 := initSyncedWatcher(t, uuid.New().String(), server)
	adapter.EXPECT().AddPolicy(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
	reader, watcher2, adapter, ctrl2 := initSyncedWatcher(t, uuid.New().String(), server)

	response, err := writer.AddPolicy("alice", "book1", "write")
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 100)
	t.Log("Policy: ", writer.GetPolicy())

	added := reader.GetPolicy()
	t.Log("Policy: ", added)
	util.ArrayEquals([]string{"alice", "book1", "write"}, added[0])

	ctrl1.Finish()
	ctrl2.Finish()

	watcher1.Close()
	watcher2.Close()
	time.Sleep(time.Millisecond * 100)
	server.Close()
}

func TestSyncedCallbackHandler_UpdateForRemovePolicy(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create to Redis server: %v", err)
	}

	writer, watcher1, adapter, ctrl1 := initSyncedWatcher(t, uuid.New().String(), server)
	adapter.EXPECT().AddPolicy(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
	adapter.EXPECT().RemovePolicy(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
	reader, watcher2, adapter, ctrl2 := initSyncedWatcher(t, uuid.New().String(), server)

	response, err := writer.AddPolicy("alice", "book1", "write")
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 10)
	t.Log("Policy: ", writer.GetPolicy())

	updated := reader.GetPolicy()
	t.Log("Policy: ", updated)
	util.ArrayEquals([]string{"alice", "book1", "write"}, updated[0])

	response, err = writer.RemovePolicy("alice", "book1", "write")
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 10)
	removed := reader.GetPolicy()
	t.Log("Policy: ", removed)
	util.Array2DEquals([][]string{{}}, removed)

	ctrl1.Finish()
	ctrl2.Finish()

	watcher1.Close()
	watcher2.Close()
	time.Sleep(time.Millisecond * 100)
	server.Close()

}

func TestSyncedCallbackHandler_UpdateForRemoveFilteredPolicy(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create to Redis server: %v", err)
	}

	writer, watcher1, adapter, ctrl1 := initSyncedWatcher(t, uuid.New().String(), server)
	adapter.EXPECT().AddPolicies(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
	adapter.EXPECT().RemoveFilteredPolicy(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
	reader, watcher2, adapter, ctrl2 := initSyncedWatcher(t, uuid.New().String(), server)

	response, err := writer.AddPolicies([][]string{{"alice", "book1", "read"}, {"alice", "book1", "write"}})
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 10)
	t.Log("Policy: ", writer.GetPolicy())

	added := reader.GetPolicy()
	t.Log("Policy: ", added)
	if !util.Array2DEquals([][]string{{"alice", "book1", "read"}, {"alice", "book1", "write"}}, added) {
		t.Fatalf("policy should be equal")
	}

	response, err = writer.RemoveFilteredPolicy(1, "book1", "read")
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 10)
	t.Log("Policy: ", writer.GetPolicy())

	synced := reader.GetPolicy()
	t.Log("Policy: ", synced)
	if !util.Array2DEquals([][]string{{"alice", "book1", "write"}}, synced) {
		t.Fatalf("policy should be equal")
	}

	ctrl1.Finish()
	ctrl2.Finish()

	watcher1.Close()
	watcher2.Close()
	time.Sleep(time.Millisecond * 100)
	server.Close()

}

func TestSyncedCallbackHandler_UpdateForAddPolicies(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create to Redis server: %v", err)
	}

	writer, watcher1, adapter, ctrl1 := initSyncedWatcher(t, uuid.New().String(), server)
	adapter.EXPECT().AddPolicies(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
	reader, watcher2, adapter, ctrl2 := initSyncedWatcher(t, uuid.New().String(), server)

	response, err := writer.AddPolicies([][]string{{"alice", "book1", "read"}, {"alice", "book1", "write"}})
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 100)
	t.Log("Policy: ", writer.GetPolicy())

	added := reader.GetPolicy()
	t.Log("Policy: ", added)
	if !util.Array2DEquals([][]string{{"alice", "book1", "read"}, {"alice", "book1", "write"}}, added) {
		t.Fatalf("policy should be equal")
	}

	ctrl1.Finish()
	ctrl2.Finish()

	watcher1.Close()
	watcher2.Close()
	time.Sleep(time.Millisecond * 100)
	server.Close()
}

func TestSyncedCallbackHandler_UpdateForRemovePolicies(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create to Redis server: %v", err)
	}

	writer, watcher1, adapter, ctrl1 := initSyncedWatcher(t, uuid.New().String(), server)
	adapter.EXPECT().AddPolicies(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
	adapter.EXPECT().RemovePolicies(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
	reader, watcher2, adapter, ctrl2 := initSyncedWatcher(t, uuid.New().String(), server)

	response, err := writer.AddPolicies([][]string{
		{"alice", "book1", "read"}, {"alice", "book1", "write"},
		{"alice", "book2", "read"}, {"alice", "book2", "write"},
	})
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 100)
	t.Log("Policy: ", writer.GetPolicy())

	added := reader.GetPolicy()
	t.Log("Policy: ", added)
	if !util.Array2DEquals([][]string{
		{"alice", "book1", "read"}, {"alice", "book1", "write"},
		{"alice", "book2", "read"}, {"alice", "book2", "write"},
	}, added) {
		t.Fatalf("policy should be equal")
	}

	response, err = writer.RemovePolicies([][]string{{"alice", "book1", "write"}, {"alice", "book2", "write"}})
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 10)
	t.Log("Policy: ", writer.GetPolicy())

	synced := reader.GetPolicy()
	t.Log("Policy: ", synced)
	if !util.Array2DEquals([][]string{{"alice", "book1", "read"}, {"alice", "book2", "read"}}, synced) {
		t.Fatalf("policy should be equal")
	}

	ctrl1.Finish()
	ctrl2.Finish()

	watcher1.Close()
	watcher2.Close()
	time.Sleep(time.Millisecond * 100)
	server.Close()
}

func TestSyncedCallbackHandler_UpdateForUpdatePolicy(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create to Redis server: %v", err)
	}

	writer, watcher1, adapter, ctrl1 := initSyncedWatcherUpdatable(t, uuid.New().String(), server)
	adapter.EXPECT().AddPolicy(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
	adapter.EXPECT().UpdatePolicy(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
	reader, watcher2, adapter, ctrl2 := initSyncedWatcherUpdatable(t, uuid.New().String(), server)

	response, err := writer.AddPolicy("alice", "book1", "write")
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 10)
	t.Log("Policy: ", writer.GetPolicy())

	added := reader.GetPolicy()
	t.Log("Policy: ", added)
	util.ArrayEquals([]string{"alice", "book1", "write"}, added[0])

	response, err = writer.UpdatePolicy([]string{"alice", "book1", "write"}, []string{"alice", "book1", "read"})
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 10)
	t.Log("Policy: ", writer.GetPolicy())

	updated := reader.GetPolicy()
	t.Log("Policy: ", updated)
	util.ArrayEquals([]string{"alice", "book1", "read"}, updated[0])

	ctrl1.Finish()
	ctrl2.Finish()

	watcher1.Close()
	watcher2.Close()
	time.Sleep(time.Millisecond * 100)
	server.Close()

}

func TestSyncedCallbackHandler_UpdateForUpdatePolicies(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create to Redis server: %v", err)
	}

	writer, watcher1, adapter, ctrl1 := initSyncedWatcherUpdatable(t, uuid.New().String(), server)
	adapter.EXPECT().AddPolicy(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(4)
	adapter.EXPECT().UpdatePolicies(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
	reader, watcher2, adapter, ctrl2 := initSyncedWatcherUpdatable(t, uuid.New().String(), server)

	response, err := writer.AddPolicy("alice", "book1", "read")
	assertResult(t, response, err)
	response, err = writer.AddPolicy("alice", "book1", "write")
	assertResult(t, response, err)
	response, err = writer.AddPolicy("alice", "book2", "read")
	assertResult(t, response, err)
	response, err = writer.AddPolicy("alice", "book2", "write")
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 100)
	t.Log("Policy: ", writer.GetPolicy())

	added := reader.GetPolicy()
	t.Log("Policy: ", added)
	if !util.Array2DEquals([][]string{
		{"alice", "book1", "read"}, {"alice", "book1", "write"},
		{"alice", "book2", "read"}, {"alice", "book2", "write"},
	}, added) {
		t.Fatalf("policy should be equal")
	}

	response, err = writer.UpdatePolicies(
		[][]string{{"alice", "book1", "write"}, {"alice", "book2", "write"}},
		[][]string{{"bob", "book1", "write"}, {"bob", "book2", "write"}},
	)
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 10)
	t.Log("Policy: ", writer.GetPolicy())

	synced := reader.GetPolicy()
	t.Log("Policy: ", synced)
	if !util.Array2DEquals([][]string{
		{"alice", "book1", "read"}, {"bob", "book1", "write"},
		{"alice", "book2", "read"}, {"bob", "book2", "write"},
	}, added) {
		t.Fatalf("policy should be equal")
	}

	ctrl1.Finish()
	ctrl2.Finish()

	watcher1.Close()
	watcher2.Close()
	time.Sleep(time.Millisecond * 100)
	server.Close()
}

func TestSyncedCallbackHandler_UpdateForUpdateFilteredPolicies(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create to Redis server: %v", err)
	}

	writer, watcher1, adapter, ctrl1 := initSyncedWatcherUpdatable(t, uuid.New().String(), server)
	adapter.EXPECT().AddPolicy(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(4)
	adapter.EXPECT().UpdateFilteredPolicies(gomock.Any(), gomock.Any(), [][]string{{"alice", "book3", "read"}, {"alice", "book3", "write"}}, 1, "book1").
		Return([][]string{{"alice", "book1", "read"}, {"alice", "book1", "write"}}, nil).Times(1)
	reader, watcher2, adapter, ctrl2 := initSyncedWatcherUpdatable(t, uuid.New().String(), server)

	response, err := writer.AddPolicy("alice", "book1", "read")
	assertResult(t, response, err)
	response, err = writer.AddPolicy("alice", "book1", "write")
	assertResult(t, response, err)
	response, err = writer.AddPolicy("alice", "book2", "read")
	assertResult(t, response, err)
	response, err = writer.AddPolicy("alice", "book2", "write")
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 100)
	t.Log("Policy: ", writer.GetPolicy())

	added := reader.GetPolicy()
	t.Log("Policy: ", added)
	if !util.Array2DEquals([][]string{
		{"alice", "book1", "read"}, {"alice", "book1", "write"},
		{"alice", "book2", "read"}, {"alice", "book2", "write"},
	}, added) {
		t.Fatalf("policy should be equal")
	}

	response, err = writer.UpdateFilteredPolicies([][]string{{"alice", "book3", "read"}, {"alice", "book3", "write"}}, 1, "book1")
	assertResult(t, response, err)
	time.Sleep(time.Millisecond * 10)
	t.Log("Policy: ", writer.GetPolicy())

	synced := reader.GetPolicy()
	t.Log("Policy: ", synced)
	if !util.Array2DEquals([][]string{
		{"alice", "book3", "read"}, {"alice", "book3", "write"},
		{"alice", "book2", "read"}, {"alice", "book2", "write"},
	}, added) {
		t.Fatalf("policy should be equal")
	}

	ctrl1.Finish()
	ctrl2.Finish()

	watcher1.Close()
	watcher2.Close()
	time.Sleep(time.Millisecond * 100)
	server.Close()
}

type enforcer struct {
	e *casbin.SyncedEnforcer
	w *rediswatcher.Watcher
	c *gomock.Controller
}

func TestSyncedCallbackHandler_UpdateForAddPolicyMultiReaders(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to create to Redis server: %v", err)
	}

	writer, watcher, adapter, ctrl := initSyncedWatcher(t, uuid.New().String(), server)
	adapter.EXPECT().AddPolicy(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
	n := 2
	readers := make([]enforcer, 0)
	for i := 0; i < n; i++ {
		reader, watcher, _, ctrl := initSyncedWatcher(t, uuid.New().String(), server)
		readers = append(readers, enforcer{e: reader, w: watcher, c: ctrl})
	}

	response, err := writer.AddPolicy("alice", "book1", "write")
	assertResult(t, response, err)

	time.Sleep(time.Millisecond * 100)
	t.Log("Policy: ", writer.GetPolicy())

	for i := 0; i < n; i++ {
		added := readers[i].e.GetPolicy()
		t.Log("Policy: ", added)
		util.ArrayEquals([]string{"alice", "book1", "write"}, added[0])
	}

	ctrl.Finish()
	watcher.Close()

	for i := 0; i < n; i++ {
		readers[i].c.Finish()
		readers[i].w.Close()
	}

	time.Sleep(time.Millisecond * 100)
	server.Close()
}
