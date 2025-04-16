package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	namespace      = "neofs_rest_gw"
	stateSubsystem = "state"
	poolSubsystem  = "pool"
)

type GateMetrics struct {
	stateMetrics
	poolMetricsCollector
}

type stateMetrics struct {
	healthCheck prometheus.Gauge
	gwVersion   *prometheus.GaugeVec
}

type poolMetricsCollector struct {
	currentErrors   *prometheus.GaugeVec
	requestDuration *prometheus.GaugeVec
}

// NewGateMetrics creates new metrics for rest gate.
func NewGateMetrics() *GateMetrics {
	stateMetric := newStateMetrics()
	stateMetric.register()

	poolMetric := newPoolMetricsCollector()
	poolMetric.register()

	return &GateMetrics{
		stateMetrics:         *stateMetric,
		poolMetricsCollector: *poolMetric,
	}
}

func newStateMetrics() *stateMetrics {
	return &stateMetrics{
		healthCheck: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: stateSubsystem,
			Name:      "health",
			Help:      "Current REST gateway state",
		}),
		gwVersion: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Help:      "Gateway version",
				Name:      "version",
				Namespace: namespace,
			},
			[]string{"version"},
		),
	}
}

func (m stateMetrics) register() {
	prometheus.MustRegister(m.healthCheck)
	prometheus.MustRegister(m.gwVersion)
}

func (m stateMetrics) SetHealth(s int32) {
	m.healthCheck.Set(float64(s))
}

func newPoolMetricsCollector() *poolMetricsCollector {
	currentErrors := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "current_errors",
			Help:      "Number of errors on current connections that will be reset after the threshold",
		},
		[]string{
			"node",
		},
	)

	requestsDuration := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "avg_request_duration",
			Help:      "Average request duration (in milliseconds) for specific method on node in pool",
		},
		[]string{
			"node",
			"method",
		},
	)

	return &poolMetricsCollector{
		currentErrors:   currentErrors,
		requestDuration: requestsDuration,
	}
}

func (m *poolMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	m.updateStatistic()
	m.currentErrors.Collect(ch)
	m.requestDuration.Collect(ch)
}

func (m poolMetricsCollector) Describe(descs chan<- *prometheus.Desc) {
	m.currentErrors.Describe(descs)
	m.requestDuration.Describe(descs)
}

func (m *poolMetricsCollector) register() {
	prometheus.MustRegister(m)
}

func (m *poolMetricsCollector) updateStatistic() {
	m.currentErrors.Reset()
	m.requestDuration.Reset()
}

// NewPrometheusService creates a new service for gathering prometheus metrics.
func NewPrometheusService(log *zap.Logger, cfg Config) *Service {
	if log == nil {
		return nil
	}

	return &Service{
		Server: &http.Server{
			Addr:    cfg.Address,
			Handler: promhttp.Handler(),
		},
		enabled:     cfg.Enabled,
		serviceType: "Prometheus",
		log:         log.With(zap.String("service", "Prometheus")),
	}
}

func (g *GateMetrics) SetGWVersion(ver string) {
	g.gwVersion.WithLabelValues(ver).Add(1)
}
