package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Logger *zap.SugaredLogger

func init() {
	conf := zap.NewDevelopmentConfig()
	conf.DisableCaller = true
	conf.DisableStacktrace = true
	conf.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder

	logger, _ := conf.Build()
	Logger = logger.Sugar()
}

func SetLogger(l *zap.SugaredLogger) {
	Logger = l
}
