package rediswatcher

import (
	"context"
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
	return nil,nil
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
