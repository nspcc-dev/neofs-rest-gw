package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neo-go/cli/flags"
	"github.com/nspcc-dev/neo-go/cli/input"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi"
	"github.com/nspcc-dev/neofs-rest-gw/handlers"
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	defaultConnectTimeout     = 10 * time.Second
	defaultHealthcheckTimeout = 15 * time.Second
	defaultRebalanceTimer     = 60 * time.Second

	defaultShutdownTimeout = 15 * time.Second

	defaultPoolErrorThreshold uint32 = 100

	// Pool config.
	cfgNodeDialTimeout    = "node-dial-timeout"
	cfgHealthcheckTimeout = "healthcheck-timeout"
	cfgRebalance          = "rebalance-timer"
	cfgPoolErrorThreshold = "pool-error-threshold"

	// Metrics / Profiler.
	cfgPrometheusEnabled = "prometheus.enabled"
	cfgPrometheusAddress = "prometheus.address"
	cfgPprofEnabled      = "pprof.enabled"
	cfgPprofAddress      = "pprof.address"

	// Logger.
	cfgLoggerLevel = "logger.level"

	// Wallet.
	cfgWalletPath       = "wallet.path"
	cfgWalletAddress    = "wallet.address"
	cfgWalletPassphrase = "wallet.passphrase"

	// Peers.
	cfgPeers = "peers"

	// Command line args.
	cmdHelp    = "help"
	cmdVersion = "version"
	cmdPprof   = "pprof"
	cmdMetrics = "metrics"
	cmdWallet  = "wallet"
	cmdAddress = "address"
	cmdConfig  = "config"
)

var ignore = map[string]struct{}{
	cfgPeers:   {},
	cmdHelp:    {},
	cmdVersion: {},
}

// Prefix is a prefix used for environment variables containing gateway
// configuration.
const Prefix = "REST_GW"

var (
	// Version is gateway version.
	Version = "dev"
)

func config() *viper.Viper {
	v := viper.New()
	v.AutomaticEnv()
	v.SetEnvPrefix(Prefix)
	v.AllowEmptyEnv(true)
	v.SetConfigType("yaml")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	// flags setup:
	flagSet := pflag.NewFlagSet("commandline", pflag.ExitOnError)
	flagSet.SetOutput(os.Stdout)
	flagSet.SortFlags = false

	flagSet.Bool(cmdPprof, false, "enable pprof")
	flagSet.Bool(cmdMetrics, false, "enable prometheus")

	help := flagSet.BoolP(cmdHelp, "h", false, "show help")
	version := flagSet.BoolP(cmdVersion, "v", false, "show version")

	flagSet.StringP(cmdWallet, "w", "", `path to the wallet`)
	flagSet.String(cmdAddress, "", `address of wallet account`)
	config := flagSet.String(cmdConfig, "", "config path")
	flagSet.Duration(cfgNodeDialTimeout, defaultConnectTimeout, "gRPC node connect timeout")
	flagSet.Duration(cfgHealthcheckTimeout, defaultHealthcheckTimeout, "gRPC healthcheck timeout")
	flagSet.Duration(cfgRebalance, defaultRebalanceTimer, "gRPC connection rebalance timer")

	peers := flagSet.StringArrayP(cfgPeers, "p", nil, "NeoFS nodes")

	// init server flags
	restapi.BindDefaultFlags(flagSet)

	// set defaults:
	// pool
	v.SetDefault(cfgPoolErrorThreshold, defaultPoolErrorThreshold)

	// metrics
	v.SetDefault(cfgPprofAddress, "localhost:8091")
	v.SetDefault(cfgPrometheusAddress, "localhost:8092")

	// logger:
	v.SetDefault(cfgLoggerLevel, "debug")

	// Bind flags
	if err := v.BindPFlag(cfgPprofEnabled, flagSet.Lookup(cmdPprof)); err != nil {
		panic(err)
	}
	if err := v.BindPFlag(cfgPrometheusEnabled, flagSet.Lookup(cmdMetrics)); err != nil {
		panic(err)
	}

	if err := v.BindPFlags(flagSet); err != nil {
		panic(err)
	}

	if err := flagSet.Parse(os.Args); err != nil {
		panic(err)
	}

	switch {
	case help != nil && *help:
		fmt.Printf("NeoFS REST Gateway %s\n", Version)
		flagSet.PrintDefaults()

		fmt.Println()
		fmt.Println("Default environments:")
		fmt.Println()
		cmdKeys := v.AllKeys()
		sort.Strings(cmdKeys)

		for i := range cmdKeys {
			if _, ok := ignore[cmdKeys[i]]; ok {
				continue
			}

			k := strings.Replace(cmdKeys[i], ".", "_", -1)
			fmt.Printf("%s_%s = %v\n", Prefix, strings.ToUpper(k), v.Get(cmdKeys[i]))
		}

		os.Exit(0)
	case version != nil && *version:
		fmt.Printf("NeoFS REST Gateway %s\n", Version)
		os.Exit(0)
	}

	if v.IsSet(cmdConfig) {
		if cfgFile, err := os.Open(*config); err != nil {
			panic(err)
		} else if err := v.ReadConfig(cfgFile); err != nil {
			panic(err)
		}
	}

	if peers != nil && len(*peers) > 0 {
		for i := range *peers {
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+".address", (*peers)[i])
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+".weight", 1)
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+".priority", 1)
		}
	}

	return v
}

func getNeoFSKey(logger *zap.Logger, cfg *viper.Viper) (*keys.PrivateKey, error) {
	walletPath := cfg.GetString(cmdWallet)
	if len(walletPath) == 0 {
		walletPath = cfg.GetString(cfgWalletPath)
	}

	if len(walletPath) == 0 {
		logger.Info("no wallet path specified, creating ephemeral key automatically for this run")
		return keys.NewPrivateKey()
	}
	w, err := wallet.NewWalletFromFile(walletPath)
	if err != nil {
		return nil, err
	}

	var password *string
	if cfg.IsSet(cfgWalletPassphrase) {
		pwd := cfg.GetString(cfgWalletPassphrase)
		password = &pwd
	}

	address := cfg.GetString(cmdAddress)
	if len(address) == 0 {
		address = cfg.GetString(cfgWalletAddress)
	}

	return getKeyFromWallet(w, address, password)
}

func getKeyFromWallet(w *wallet.Wallet, addrStr string, password *string) (*keys.PrivateKey, error) {
	var addr util.Uint160
	var err error

	if addrStr == "" {
		addr = w.GetChangeAddress()
	} else {
		addr, err = flags.ParseAddress(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid address")
		}
	}

	acc := w.GetAccount(addr)
	if acc == nil {
		return nil, fmt.Errorf("couldn't find wallet account for %s", addrStr)
	}

	if password == nil {
		pwd, err := input.ReadPassword("Enter password > ")
		if err != nil {
			return nil, fmt.Errorf("couldn't read password")
		}
		password = &pwd
	}

	if err := acc.Decrypt(*password, w.Scrypt); err != nil {
		return nil, fmt.Errorf("couldn't decrypt account: %w", err)
	}

	return acc.PrivateKey(), nil
}

// newLogger constructs a zap.Logger instance for current application.
// Panics on failure.
//
// Logger is built from zap's production logging configuration with:
//   - parameterized level (debug by default)
//   - console encoding
//   - ISO8601 time encoding
//
// Logger records a stack trace for all messages at or above fatal level.
//
// See also zapcore.Level, zap.NewProductionConfig, zap.AddStacktrace.
func newLogger(v *viper.Viper) *zap.Logger {
	var lvl zapcore.Level
	lvlStr := v.GetString(cfgLoggerLevel)
	err := lvl.UnmarshalText([]byte(lvlStr))
	if err != nil {
		panic(fmt.Sprintf("incorrect logger level configuration %s (%v), "+
			"value should be one of %v", lvlStr, err, [...]zapcore.Level{
			zapcore.DebugLevel,
			zapcore.InfoLevel,
			zapcore.WarnLevel,
			zapcore.ErrorLevel,
			zapcore.DPanicLevel,
			zapcore.PanicLevel,
			zapcore.FatalLevel,
		}))
	}

	c := zap.NewProductionConfig()
	c.Level = zap.NewAtomicLevelAt(lvl)
	c.Encoding = "console"
	c.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	l, err := c.Build(
		zap.AddStacktrace(zap.NewAtomicLevelAt(zap.FatalLevel)),
	)
	if err != nil {
		panic(fmt.Sprintf("build zap logger instance: %v", err))
	}

	return l
}

func serverConfig(v *viper.Viper) *restapi.ServerConfig {
	return &restapi.ServerConfig{
		EnabledListeners: v.GetStringSlice(restapi.FlagScheme),
		CleanupTimeout:   v.GetDuration(restapi.FlagCleanupTimeout),
		GracefulTimeout:  v.GetDuration(restapi.FlagGracefulTimeout),
		MaxHeaderSize:    v.GetInt(restapi.FlagMaxHeaderSize),

		ListenAddress: v.GetString(restapi.FlagListenAddress),
		ListenLimit:   v.GetInt(restapi.FlagListenLimit),
		KeepAlive:     v.GetDuration(restapi.FlagKeepAlive),
		ReadTimeout:   v.GetDuration(restapi.FlagReadTimeout),
		WriteTimeout:  v.GetDuration(restapi.FlagWriteTimeout),

		TLSListenAddress: v.GetString(restapi.FlagTLSListenAddress),
		TLSListenLimit:   v.GetInt(restapi.FlagTLSListenLimit),
		TLSKeepAlive:     v.GetDuration(restapi.FlagTLSKeepAlive),
		TLSReadTimeout:   v.GetDuration(restapi.FlagTLSReadTimeout),
		TLSWriteTimeout:  v.GetDuration(restapi.FlagTLSWriteTimeout),
	}
}

func newNeofsAPI(ctx context.Context, logger *zap.Logger, v *viper.Viper) (*handlers.API, error) {
	key, err := getNeoFSKey(logger, v)
	if err != nil {
		return nil, err
	}

	var prm pool.InitParameters
	prm.SetKey(&key.PrivateKey)
	prm.SetNodeDialTimeout(v.GetDuration(cfgNodeDialTimeout))
	prm.SetHealthcheckTimeout(v.GetDuration(cfgHealthcheckTimeout))
	prm.SetClientRebalanceInterval(v.GetDuration(cfgRebalance))
	prm.SetErrorThreshold(v.GetUint32(cfgPoolErrorThreshold))

	for _, peer := range fetchPeers(logger, v) {
		prm.AddNode(peer)
	}

	p, err := pool.NewPool(prm)
	if err != nil {
		return nil, err
	}

	if err = p.Dial(ctx); err != nil {
		return nil, err
	}

	var apiPrm handlers.PrmAPI
	apiPrm.Pool = p
	apiPrm.Key = key
	apiPrm.Logger = logger

	pprofConfig := metrics.Config{Enabled: v.GetBool(cfgPprofEnabled), Address: v.GetString(cfgPprofAddress)}
	apiPrm.PprofService = metrics.NewPprofService(logger, pprofConfig)

	prometheusConfig := metrics.Config{Enabled: v.GetBool(cfgPrometheusEnabled), Address: v.GetString(cfgPrometheusAddress)}
	apiPrm.PrometheusService = metrics.NewPrometheusService(logger, prometheusConfig)
	if prometheusConfig.Enabled {
		apiPrm.GateMetric = metrics.NewGateMetrics(p)
	}

	apiPrm.ServiceShutdownTimeout = defaultShutdownTimeout

	return handlers.New(&apiPrm), nil
}

func fetchPeers(l *zap.Logger, v *viper.Viper) []pool.NodeParam {
	var nodes []pool.NodeParam
	for i := 0; ; i++ {
		key := cfgPeers + "." + strconv.Itoa(i) + "."
		address := v.GetString(key + "address")
		weight := v.GetFloat64(key + "weight")
		priority := v.GetInt(key + "priority")

		if address == "" {
			break
		}
		if weight <= 0 { // unspecified or wrong
			weight = 1
		}
		if priority <= 0 { // unspecified or wrong
			priority = 1
		}

		nodes = append(nodes, pool.NewNodeParam(priority, address, weight))

		l.Info("added connection peer",
			zap.String("address", address),
			zap.Int("priority", priority),
			zap.Float64("weight", weight),
		)
	}

	return nodes
}
