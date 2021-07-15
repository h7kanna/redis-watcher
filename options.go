package rediswatcher

import (
	"context"
	"fmt"
	"net"

	rds "github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

type Logger interface {
	Printf(ctx context.Context, format string, v ...interface{})
}

type WatcherMetrics struct {
	Name        string
	LatencyMs   float64
	LocalID     string
	Channel     string
	Protocol    string
	Error       error
	MessageSize int64
}

const (
	RedisDoAuthMetric       = "RedisDoAuth"
	RedisCloseMetric        = "RedisClose"
	RedisDialMetric         = "RedisDial"
	PubSubPublishMetric     = "PubSubPublish"
	PubSubReceiveMetric     = "PubSubReceive"
	PubSubSubscribeMetric   = "PubSubSubscribe"
	PubSubUnsubscribeMetric = "PubSubUnsubscribe"
)

func Dialer(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, nil
}

type DefaultHook struct{}

var _ rds.Hook = DefaultHook{}

func (DefaultHook) BeforeProcess(ctx context.Context, cmd rds.Cmder) (context.Context, error) {
	fmt.Printf("starting processing: <%s>\n", cmd)
	return ctx, nil
}

func (DefaultHook) AfterProcess(ctx context.Context, cmd rds.Cmder) error {
	fmt.Printf("finished processing: <%s>\n", cmd)
	return nil
}

func (DefaultHook) BeforeProcessPipeline(ctx context.Context, cmds []rds.Cmder) (context.Context, error) {
	fmt.Printf("pipeline starting processing: %v\n", cmds)
	return ctx, nil
}

func (DefaultHook) AfterProcessPipeline(ctx context.Context, cmds []rds.Cmder) error {
	fmt.Printf("pipeline finished processing: %v\n", cmds)
	return nil
}

type WatcherOptions struct {
	rds.Options
	SubClient              *rds.Client
	PubClient              *rds.Client
	Hooks                  []rds.Hook
	Logger                 Logger
	Channel                string
	IgnoreSelf             bool
	LocalID                string
	OptionalUpdateCallback func(string)
}

func initConfig(option *WatcherOptions) {
	if option.LocalID == "" {
		option.LocalID = uuid.New().String()
	}
	if option.Channel == "" {
		option.Channel = "/casbin"
	}
}
