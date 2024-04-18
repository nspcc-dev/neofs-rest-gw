package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nspcc-dev/neo-go/cli/flags"
	"github.com/nspcc-dev/neo-go/cli/input"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
	"github.com/nspcc-dev/neofs-rest-gw/handlers"
	"github.com/nspcc-dev/neofs-rest-gw/metrics"
	"github.com/nspcc-dev/neofs-sdk-go/client"
	"github.com/nspcc-dev/neofs-sdk-go/pool"
	"github.com/nspcc-dev/neofs-sdk-go/stat"
	"github.com/nspcc-dev/neofs-sdk-go/user"
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
	cmdNodeDialTimeout    = "node-dial-timeout"
	cfgNodeDialTimeout    = "pool." + cmdNodeDialTimeout
	cmdHealthcheckTimeout = "healthcheck-timeout"
	cfgHealthcheckTimeout = "pool." + cmdHealthcheckTimeout
	cmdRebalance          = "rebalance-timer"
	cfgRebalance          = "pool." + cmdRebalance
	cfgPoolErrorThreshold = "pool.error-threshold"
	cmdPeers              = "peers"
	cfgPeers              = "pool." + cmdPeers
	cfgPeerAddress        = "address"
	cfgPeerPriority       = "priority"
	cfgPeerWeight         = "weight"

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

	// Server endpoints.
	cfgServerSection   = "server."
	cfgServerEndpoints = cfgServerSection + "endpoints"

	cfgTLSEnabled    = "tls.enabled"
	cfgTLSKeyFile    = "tls.key"
	cfgTLSCertFile   = "tls.certificate"
	cfgTLSCertCAFile = "tls.ca-certificate"

	cfgEndpointAddress         = "address"
	cfgEndpointExternalAddress = "external-address"
	cfgEndpointKeepAlive       = "keep-alive"
	cfgEndpointReadTimeout     = "read-timeout"
	cfgEndpointWriteTimeout    = "write-timeout"

	// Command line args.
	cmdHelp          = "help"
	cmdVersion       = "version"
	cmdPprof         = "pprof"
	cmdMetrics       = "metrics"
	cmdWallet        = "wallet"
	cmdAddress       = "address"
	cmdConfig        = "config"
	cmdListenAddress = "listen-address"

	baseURL = "/v1"
)

var ignore = map[string]struct{}{
	cmdPeers:   {},
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

	configFlag := flagSet.String(cmdConfig, "", "config path")
	flagSet.Duration(cmdNodeDialTimeout, defaultConnectTimeout, "gRPC node connect timeout")
	flagSet.Duration(cmdHealthcheckTimeout, defaultHealthcheckTimeout, "gRPC healthcheck timeout")
	flagSet.Duration(cmdRebalance, defaultRebalanceTimer, "gRPC connection rebalance timer")

	peers := flagSet.StringArrayP(cmdPeers, "p", nil, "NeoFS nodes")

	flagSet.String(cmdListenAddress, "localhost:8080", "set the main address to listen")
	flagSet.String(cfgTLSCertFile, "", "TLS certificate file to use; note that if you want to start HTTPS server, you should also set up --"+cmdListenAddress+" and --"+cfgTLSKeyFile)
	flagSet.String(cfgTLSKeyFile, "", "TLS key file to use; note that if you want to start HTTPS server, you should also set up --"+cmdListenAddress+" and --"+cfgTLSCertFile)
	flagSet.Duration(cfgEndpointKeepAlive, 3*time.Minute, "sets the TCP keep-alive timeouts on accepted connections. It prunes dead TCP connections ( e.g. closing laptop mid-download)")
	flagSet.Duration(cfgEndpointReadTimeout, 30*time.Second, "maximum duration before timing out read of the request")
	flagSet.Duration(cfgEndpointWriteTimeout, 30*time.Second, "maximum duration before timing out write of the response")
	flagSet.String(cfgEndpointExternalAddress, "localhost:8090", "the IP and port to be shown in the API documentation")

	// init server flags
	BindDefaultFlags(flagSet)

	if err := bindServerFlags(v, flagSet); err != nil {
		panic(fmt.Errorf("bind server flags: %w", err))
	}
	// set defaults:
	// pool
	v.SetDefault(cfgPoolErrorThreshold, defaultPoolErrorThreshold)

	// metrics
	v.SetDefault(cfgPprofAddress, "localhost:8091")
	v.SetDefault(cfgPrometheusAddress, "localhost:8092")

	// logger:
	v.SetDefault(cfgLoggerLevel, "debug")

	// Bind flags
	for cfg, cmd := range bindings {
		if err := v.BindPFlag(cfg, flagSet.Lookup(cmd)); err != nil {
			panic(fmt.Errorf("bind flags: %w", err))
		}
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
		fmt.Printf("NeoFS REST Gateway\nVersion: %s\nGoVersion: %s\n", Version, runtime.Version())
		os.Exit(0)
	case configFlag != nil && *configFlag != "":
		if cfgFile, err := os.Open(*configFlag); err != nil {
			panic(err)
		} else if err = v.ReadConfig(cfgFile); err != nil {
			panic(err)
		}
	}

	if peers != nil && len(*peers) > 0 {
		for i := range *peers {
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+"."+cfgPeerAddress, (*peers)[i])
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+"."+cfgPeerWeight, 1)
			v.SetDefault(cfgPeers+"."+strconv.Itoa(i)+"."+cfgPeerWeight, 1)
		}
	}

	return v
}

func bindServerFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	// This key is used only to check if the address comes from the command arguments.
	if err := v.BindPFlag(cmdListenAddress, flags.Lookup(cmdListenAddress)); err != nil {
		return err
	}

	if err := v.BindPFlag(cfgServerEndpoints+".0."+cfgEndpointAddress, flags.Lookup(cmdListenAddress)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgServerEndpoints+".0."+cfgEndpointExternalAddress, flags.Lookup(cfgEndpointExternalAddress)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgServerEndpoints+".0."+cfgEndpointKeepAlive, flags.Lookup(cfgEndpointKeepAlive)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgServerEndpoints+".0."+cfgEndpointReadTimeout, flags.Lookup(cfgEndpointReadTimeout)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgServerEndpoints+".0."+cfgEndpointWriteTimeout, flags.Lookup(cfgEndpointWriteTimeout)); err != nil {
		return err
	}
	if err := v.BindPFlag(cfgServerEndpoints+".0."+cfgTLSKeyFile, flags.Lookup(cfgTLSKeyFile)); err != nil {
		return err
	}

	return v.BindPFlag(cfgServerEndpoints+".0."+cfgTLSCertFile, flags.Lookup(cfgTLSCertFile))
}

func init() {
	for _, flagName := range serverFlags {
		cfgName := cfgServerSection + flagName
		bindings[cfgName] = flagName
		knownConfigParams[cfgName] = struct{}{}
	}
}

var serverFlags = []string{
	FlagCleanupTimeout,
	FlagGracefulTimeout,
	FlagMaxHeaderSize,
	FlagListenLimit,
}

var bindings = map[string]string{
	cfgPprofEnabled:       cmdPprof,
	cfgPrometheusEnabled:  cmdMetrics,
	cfgNodeDialTimeout:    cmdNodeDialTimeout,
	cfgHealthcheckTimeout: cmdHealthcheckTimeout,
	cfgRebalance:          cmdRebalance,
	cfgWalletPath:         cmdWallet,
	cfgWalletAddress:      cmdAddress,
}

var knownConfigParams = map[string]struct{}{
	cfgWalletAddress:      {},
	cfgWalletPath:         {},
	cfgWalletPassphrase:   {},
	cfgRebalance:          {},
	cfgHealthcheckTimeout: {},
	cfgNodeDialTimeout:    {},
	cfgPoolErrorThreshold: {},
	cfgLoggerLevel:        {},
	cfgPrometheusEnabled:  {},
	cfgPrometheusAddress:  {},
	cfgPprofEnabled:       {},
	cfgPprofAddress:       {},
}

func validateConfig(cfg *viper.Viper, logger *zap.Logger) {
	peerNumsMap := make(map[int]struct{})

	for _, providedKey := range cfg.AllKeys() {
		if !strings.HasPrefix(providedKey, cfgPeers) {
			if strings.HasPrefix(providedKey, cfgServerEndpoints) {
				// Do not validate `Endpoints` section.
				continue
			}
			if _, ok := knownConfigParams[providedKey]; !ok {
				logger.Warn("unknown config parameter", zap.String("key", providedKey))
			}
			continue
		}

		num, ok := isValidPeerKey(providedKey)
		if !ok {
			logger.Warn("unknown config parameter", zap.String("key", providedKey))
		} else {
			peerNumsMap[num] = struct{}{}
		}
	}

	peerNums := make([]int, 0, len(peerNumsMap))
	for num := range peerNumsMap {
		peerNums = append(peerNums, num)
	}
	sort.Ints(peerNums)

	for i, num := range peerNums {
		if i != num {
			logger.Warn("invalid config parameter, peer indexes must be consecutive starting from 0", zap.String("key", cfgPeers+"."+strconv.Itoa(num)))
		}
	}
}

func isValidPeerKey(key string) (int, bool) {
	trimmed := strings.TrimPrefix(key, cfgPeers)
	split := strings.Split(trimmed, ".")

	if len(split) != 3 {
		return 0, false
	}

	if split[2] != cfgPeerAddress && split[2] != cfgPeerPriority && split[2] != cfgPeerWeight {
		return 0, false
	}

	num, err := strconv.Atoi(split[1])
	if err != nil || num < 0 {
		return 0, false
	}

	return num, true
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
			return nil, fmt.Errorf("invalid address: %w", err)
		}
	}

	acc := w.GetAccount(addr)
	if acc == nil {
		return nil, fmt.Errorf("couldn't find wallet account for %s", addrStr)
	}

	if password == nil {
		pwd, err := input.ReadPassword("Enter password > ")
		if err != nil {
			return nil, fmt.Errorf("couldn't read password: %w", err)
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

// ServerConfig contains parsed config for the Echo server.
type ServerConfig struct {
	CleanupTimeout  time.Duration
	GracefulTimeout time.Duration
	MaxHeaderSize   int
	ListenLimit     int
	Endpoints       []EndpointInfo
}

const (
	FlagCleanupTimeout  = "cleanup-timeout"
	FlagGracefulTimeout = "graceful-timeout"
	FlagMaxHeaderSize   = "max-header-size"
	FlagListenLimit     = "listen-limit"
)

func BindDefaultFlags(flagSet *pflag.FlagSet) {
	flagSet.Duration(FlagCleanupTimeout, 10*time.Second, "grace period for which to wait before killing idle connections")
	flagSet.Duration(FlagGracefulTimeout, 15*time.Second, "grace period for which to wait before shutting down the server")
	flagSet.Int(FlagMaxHeaderSize, 1000000, "controls the maximum number of bytes the server will read parsing the request header's keys and values, including the request line. It does not limit the size of the request body")
	flagSet.Int(FlagListenLimit, 0, "limit the number of outstanding requests")
}

func serverConfig(v *viper.Viper) *ServerConfig {
	return &ServerConfig{
		CleanupTimeout:  v.GetDuration(cfgServerSection + FlagCleanupTimeout),
		GracefulTimeout: v.GetDuration(cfgServerSection + FlagGracefulTimeout),
		MaxHeaderSize:   v.GetInt(cfgServerSection + FlagMaxHeaderSize),
		ListenLimit:     v.GetInt(cfgServerSection + FlagListenLimit),
		Endpoints:       fetchEndpoints(v),
	}
}

func fetchEndpoints(v *viper.Viper) []EndpointInfo {
	var servers []EndpointInfo

	if v.IsSet(cmdListenAddress) {
		key := cfgServerEndpoints + ".0."
		// If this address is set, we don't use config file to set other parameters.
		serverInfo := EndpointInfo{
			Address:         v.GetString(key + cfgEndpointAddress),
			ExternalAddress: v.GetString(key + cfgEndpointExternalAddress),
			KeepAlive:       v.GetDuration(key + cfgEndpointKeepAlive),
			ReadTimeout:     v.GetDuration(key + cfgEndpointReadTimeout),
			WriteTimeout:    v.GetDuration(key + cfgEndpointWriteTimeout),
		}
		keyFile := v.GetString(key + cfgTLSKeyFile)
		certFile := v.GetString(key + cfgTLSCertFile)
		if keyFile != "" && certFile != "" {
			// If TLS key and certificate are set in the command arguments, we enable TLS.
			serverInfo.TLS.Enabled = true
			serverInfo.TLS.KeyFile = keyFile
			serverInfo.TLS.CertFile = certFile
		}
		servers = append(servers, serverInfo)
	} else {
		for i := 0; ; i++ {
			key := cfgServerEndpoints + "." + strconv.Itoa(i) + "."

			var serverInfo EndpointInfo
			serverInfo.Address = v.GetString(key + cfgEndpointAddress)
			if serverInfo.Address == "" {
				break
			}
			serverInfo.ExternalAddress = v.GetString(key + cfgEndpointExternalAddress)
			serverInfo.KeepAlive = v.GetDuration(key + cfgEndpointKeepAlive)
			serverInfo.ReadTimeout = v.GetDuration(key + cfgEndpointReadTimeout)
			serverInfo.WriteTimeout = v.GetDuration(key + cfgEndpointWriteTimeout)
			serverInfo.TLS.Enabled = v.GetBool(key + cfgTLSEnabled)
			serverInfo.TLS.KeyFile = v.GetString(key + cfgTLSKeyFile)
			serverInfo.TLS.CertFile = v.GetString(key + cfgTLSCertFile)
			serverInfo.TLS.CertCAFile = v.GetString(key + cfgTLSCertCAFile)

			servers = append(servers, serverInfo)
		}
	}

	return servers
}

func newNeofsAPI(ctx context.Context, logger *zap.Logger, v *viper.Viper) (*handlers.RestAPI, error) {
	key, err := getNeoFSKey(logger, v)
	if err != nil {
		return nil, err
	}

	var prm pool.InitParameters
	prm.SetSigner(user.NewAutoIDSignerRFC6979(key.PrivateKey))
	prm.SetNodeDialTimeout(v.GetDuration(cfgNodeDialTimeout))
	prm.SetHealthcheckTimeout(v.GetDuration(cfgHealthcheckTimeout))
	prm.SetClientRebalanceInterval(v.GetDuration(cfgRebalance))
	prm.SetErrorThreshold(v.GetUint32(cfgPoolErrorThreshold))

	poolStat := stat.NewPoolStatistic()
	prm.SetStatisticCallback(poolStat.OperationCallback)

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

	ni, err := p.NetworkInfo(ctx, client.PrmNetworkInfo{})
	if err != nil {
		return nil, fmt.Errorf("networkInfo: %w", err)
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
		apiPrm.GateMetric = metrics.NewGateMetrics(poolStat)
		apiPrm.GateMetric.SetGWVersion(Version)
	}

	apiPrm.ServiceShutdownTimeout = defaultShutdownTimeout
	apiPrm.MaxObjectSize = int64(ni.MaxObjectSize())

	return handlers.NewAPI(&apiPrm), nil
}

func fetchPeers(l *zap.Logger, v *viper.Viper) []pool.NodeParam {
	var nodes []pool.NodeParam
	for i := 0; ; i++ {
		key := cfgPeers + "." + strconv.Itoa(i) + "."
		address := v.GetString(key + cfgPeerAddress)
		weight := v.GetFloat64(key + cfgPeerWeight)
		priority := v.GetInt(key + cfgPeerPriority)

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
