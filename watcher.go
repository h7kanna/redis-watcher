package rediswatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/casbin/casbin/v2/model"

	"github.com/casbin/casbin/v2/persist"
	rds "github.com/go-redis/redis/v8"
)

type Watcher struct {
	l         sync.Mutex
	subClient *rds.Client
	pubClient *rds.Client
	options   WatcherOptions
	close     chan struct{}
	callback  func(string)
	ctx       context.Context
	log       Logger
}

type MSG struct {
	Method string
	ID     string
	Sec    string
	Ptype  string
	Params interface{}
}

type Updates struct {
	OldRule interface{}
	NewRule interface{}
}

func (m *MSG) MarshalBinary() ([]byte, error) {
	return json.Marshal(m)
}

// UnmarshalBinary decodes the struct into a User
func (m *MSG) UnmarshalBinary(data []byte) error {
	if err := json.Unmarshal(data, m); err != nil {
		return err
	}
	return nil
}

// NewWatcher creates a new Watcher to be used with a Casbin enforcer
// addr is a redis target string in the format "host:port"
// setters allows for inline WatcherOptions
//
// 		Example:
// 				w, err := rediswatcher.NewWatcher("127.0.0.1:6379",WatcherOptions{}, nil)
//
func NewWatcher(addr string, option WatcherOptions) (persist.Watcher, error) {
	option.Addr = addr
	initConfig(&option)
	w := &Watcher{
		ctx:   context.Background(),
		close: make(chan struct{}),
	}

	w.initConfig(option)

	if err := w.subClient.Ping(w.ctx).Err(); err != nil {
		return nil, err
	}
	if err := w.pubClient.Ping(w.ctx).Err(); err != nil {
		return nil, err
	}

	w.options = option

	w.subscribe()

	return w, nil
}

func (w *Watcher) initConfig(option WatcherOptions) error {
	var err error
	if option.OptionalUpdateCallback != nil {
		err = w.SetUpdateCallback(option.OptionalUpdateCallback)
	} else {
		err = w.SetUpdateCallback(func(string) {
			log.Println("Casbin Redis Watcher callback not set when an update was received")
		})
	}
	if err != nil {
		return err
	}

	if option.Logger != nil {
		rds.SetLogger(option.Logger)
	}

	if option.SubClient != nil {
		w.subClient = option.SubClient
	} else {
		w.subClient = rds.NewClient(&option.Options)
	}
	for _, h := range option.Hooks {
		w.subClient.AddHook(h)
	}

	if option.PubClient != nil {
		w.pubClient = option.PubClient
	} else {
		w.pubClient = rds.NewClient(&option.Options)
	}
	for _, h := range option.Hooks {
		w.pubClient.AddHook(h)
	}
	return nil
}

// NewPublishWatcher return a Watcher only publish but not subscribe
func NewPublishWatcher(addr string, option WatcherOptions) (persist.Watcher, error) {
	option.Addr = addr
	w := &Watcher{
		pubClient: rds.NewClient(&option.Options),
		ctx:       context.Background(),
		close:     make(chan struct{}),
	}

	initConfig(&option)
	w.options = option

	return w, nil
}

// SetUpdateCallback SetUpdateCallBack sets the update callback function invoked by the watcher
// when the policy is updated. Defaults to Enforcer.LoadPolicy()
func (w *Watcher) SetUpdateCallback(callback func(string)) error {
	w.l.Lock()
	w.callback = callback
	w.l.Unlock()
	return nil
}

// Update publishes a message to all other casbin instances telling them to
// invoke their update callback
func (w *Watcher) Update() error {
	return w.logRecord(func() error {
		w.l.Lock()
		defer w.l.Unlock()
		return w.pubClient.Publish(context.Background(), w.options.Channel, &MSG{"Update", w.options.LocalID, "", "", ""}).Err()
	})
}

// UpdateForAddPolicy calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.AddPolicy()
func (w *Watcher) UpdateForAddPolicy(sec, ptype string, params ...string) error {
	return w.logRecord(func() error {
		w.l.Lock()
		defer w.l.Unlock()
		return w.pubClient.Publish(context.Background(), w.options.Channel, &MSG{"UpdateForAddPolicy", w.options.LocalID, sec, ptype, params}).Err()
	})
}

// UpdateForRemovePolicy UPdateForRemovePolicy calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.RemovePolicy()
func (w *Watcher) UpdateForRemovePolicy(sec, ptype string, params ...string) error {
	return w.logRecord(func() error {
		w.l.Lock()
		defer w.l.Unlock()
		return w.pubClient.Publish(context.Background(), w.options.Channel, &MSG{"UpdateForRemovePolicy", w.options.LocalID, sec, ptype, params}).Err()
	})
}

// UpdateForRemoveFilteredPolicy calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.RemoveFilteredNamedGroupingPolicy()
func (w *Watcher) UpdateForRemoveFilteredPolicy(sec, ptype string, fieldIndex int, fieldValues ...string) error {
	return w.logRecord(func() error {
		w.l.Lock()
		defer w.l.Unlock()
		return w.pubClient.Publish(context.Background(), w.options.Channel,
			&MSG{"UpdateForRemoveFilteredPolicy", w.options.LocalID,
				sec,
				ptype,
				fmt.Sprintf("%d %s", fieldIndex, strings.Join(fieldValues, " ")),
			},
		).Err()
	})
}

// UpdateForSavePolicy calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.RemoveFilteredNamedGroupingPolicy()
func (w *Watcher) UpdateForSavePolicy(model model.Model) error {
	return w.logRecord(func() error {
		w.l.Lock()
		defer w.l.Unlock()
		return w.pubClient.Publish(context.Background(), w.options.Channel, &MSG{"UpdateForSavePolicy", w.options.LocalID, "", "", model}).Err()
	})
}

// UpdateForAddPolicies calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.AddPolicies()
func (w *Watcher) UpdateForAddPolicies(sec string, ptype string, params ...[]string) error {
	return w.logRecord(func() error {
		w.l.Lock()
		defer w.l.Unlock()
		return w.pubClient.Publish(context.Background(), w.options.Channel, &MSG{"UpdateForAddPolicies", w.options.LocalID, sec, ptype, params}).Err()
	})
}

// UpdateForRemovePolicies calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.RemovePolicies()
func (w *Watcher) UpdateForRemovePolicies(sec string, ptype string, params ...[]string) error {
	return w.logRecord(func() error {
		w.l.Lock()
		defer w.l.Unlock()
		return w.pubClient.Publish(context.Background(), w.options.Channel, &MSG{"UpdateForRemovePolicies", w.options.LocalID, sec, ptype, params}).Err()
	})
}

// UpdateForUpdatePolicy calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.UpdatePolicy()
func (w *Watcher) UpdateForUpdatePolicy(sec string, ptype string, oldRule, newRule []string) error {
	return w.logRecord(func() error {
		w.l.Lock()
		defer w.l.Unlock()
		rules := map[string]interface{}{"OldRule": oldRule, "NewRule": newRule}
		return w.pubClient.Publish(context.Background(), w.options.Channel, &MSG{"UpdateForUpdatePolicy", w.options.LocalID, sec, ptype, rules}).Err()
	})
}

// UpdateForUpdatePolicies calls the update callback of other instances to synchronize their policy.
// It is called after Enforcer.UpdatePolicies()
func (w *Watcher) UpdateForUpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	return w.logRecord(func() error {
		w.l.Lock()
		defer w.l.Unlock()
		return w.pubClient.Publish(context.Background(), w.options.Channel, &MSG{"UpdateForUpdatePolicies", w.options.LocalID, sec, ptype, &Updates{OldRule: oldRules, NewRule: newRules}}).Err()
	})
}

func (w *Watcher) UpdateForUpdateFilteredPolicies(sec, ptype string, oldRules, newRules [][]string) error {
	return w.logRecord(func() error {
		w.l.Lock()
		defer w.l.Unlock()
		return w.pubClient.Publish(context.Background(), w.options.Channel, &MSG{"UpdateForUpdateFilteredPolicies", w.options.LocalID, sec, ptype, &Updates{OldRule: oldRules, NewRule: newRules}}).Err()
	})
}

func (w *Watcher) logRecord(f func() error) error {
	err := f()
	if err != nil {
		w.log.Printf(w.ctx, "%s", err.Error())
	}
	return err
}

func (w *Watcher) unsubscribe(psc *rds.PubSub) error {
	return psc.Unsubscribe(w.ctx)
}

func (w *Watcher) subscribe() {
	w.l.Lock()
	sub := w.subClient.Subscribe(w.ctx, w.options.Channel)
	w.l.Unlock()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer func() {
			err := w.unsubscribe(sub)
			if err != nil {
				w.log.Printf(w.ctx, "%s", err.Error())
			}
			err = sub.Close()
			if err != nil {
				w.log.Printf(w.ctx, "%s", err.Error())
			}
			err = w.pubClient.Close()
			if err != nil {
				w.log.Printf(w.ctx, "%s", err.Error())
			}
			err = w.subClient.Close()
			if err != nil {
				w.log.Printf(w.ctx, "%s", err.Error())
			}
		}()
		ch := sub.Channel()
		wg.Done()
		for msg := range ch {
			select {
			case <-w.close:
				return
			default:
			}
			data := msg.Payload
			w.callback(data)
		}
	}()
	wg.Wait()
}

func (w *Watcher) GetWatcherOptions() WatcherOptions {
	w.l.Lock()
	defer w.l.Unlock()
	return w.options
}

func (w *Watcher) Close() {
	w.l.Lock()
	defer w.l.Unlock()
	close(w.close)
	w.pubClient.Publish(w.ctx, w.options.Channel, "Close")
}
