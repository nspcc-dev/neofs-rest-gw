package metrics

import (
	"net/http"

	"github.com/nspcc-dev/neofs-sdk-go/stat"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	namespace      = "neofs_rest_gw"
	stateSubsystem = "state"
	poolSubsystem  = "pool"

	methodGetBalance       = "get_balance"
	methodPutContainer     = "put_container"
	methodGetContainer     = "get_container"
	methodListContainer    = "list_container"
	methodDeleteContainer  = "delete_container"
	methodGetContainerEacl = "get_container_eacl"
	methodSetContainerEacl = "set_container_eacl"
	methodEndpointInfo     = "endpoint_info"
	methodNetworkInfo      = "network_info"
	methodPutObject        = "put_object"
	methodDeleteObject     = "delete_object"
	methodGetObject        = "get_object"
	methodHeadObject       = "head_object"
	methodRangeObject      = "range_object"
	methodCreateSession    = "create_session"
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
	poolStat            *stat.PoolStat
	overallErrors       prometheus.Gauge
	overallNodeErrors   *prometheus.GaugeVec
	overallNodeRequests *prometheus.GaugeVec
	currentErrors       *prometheus.GaugeVec
	requestDuration     *prometheus.GaugeVec
}

// NewGateMetrics creates new metrics for rest gate.
func NewGateMetrics(poolStat *stat.PoolStat) *GateMetrics {
	stateMetric := newStateMetrics()
	stateMetric.register()

	poolMetric := newPoolMetricsCollector(poolStat)
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

func newPoolMetricsCollector(poolStat *stat.PoolStat) *poolMetricsCollector {
	overallErrors := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "overall_errors",
			Help:      "Total number of errors in pool",
		},
	)

	overallNodeErrors := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "overall_node_errors",
			Help:      "Total number of errors for connection in pool",
		},
		[]string{
			"node",
		},
	)

	overallNodeRequests := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: poolSubsystem,
			Name:      "overall_node_requests",
			Help:      "Total number of requests to specific node in pool",
		},
		[]string{
			"node",
		},
	)

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
		poolStat:            poolStat,
		overallErrors:       overallErrors,
		overallNodeErrors:   overallNodeErrors,
		overallNodeRequests: overallNodeRequests,
		currentErrors:       currentErrors,
		requestDuration:     requestsDuration,
	}
}

func (m *poolMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	m.updateStatistic()
	m.overallErrors.Collect(ch)
	m.overallNodeErrors.Collect(ch)
	m.overallNodeRequests.Collect(ch)
	m.currentErrors.Collect(ch)
	m.requestDuration.Collect(ch)
}

func (m poolMetricsCollector) Describe(descs chan<- *prometheus.Desc) {
	m.overallErrors.Describe(descs)
	m.overallNodeErrors.Describe(descs)
	m.overallNodeRequests.Describe(descs)
	m.currentErrors.Describe(descs)
	m.requestDuration.Describe(descs)
}

func (m *poolMetricsCollector) register() {
	prometheus.MustRegister(m)
}

func (m *poolMetricsCollector) updateStatistic() {
	poolStat := m.poolStat.Statistic()

	m.overallNodeErrors.Reset()
	m.overallNodeRequests.Reset()
	m.currentErrors.Reset()
	m.requestDuration.Reset()

	for _, node := range poolStat.Nodes() {
		m.overallNodeErrors.WithLabelValues(node.Address()).Set(float64(node.OverallErrors()))
		m.overallNodeRequests.WithLabelValues(node.Address()).Set(float64(node.Requests()))

		m.updateRequestsDuration(node)
	}

	m.overallErrors.Set(float64(poolStat.OverallErrors()))
}

func (m *poolMetricsCollector) updateRequestsDuration(node stat.NodeStatistic) {
	m.requestDuration.WithLabelValues(node.Address(), methodGetBalance).Set(float64(node.AverageGetBalance().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodPutContainer).Set(float64(node.AveragePutContainer().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodGetContainer).Set(float64(node.AverageGetContainer().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodListContainer).Set(float64(node.AverageListContainer().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodDeleteContainer).Set(float64(node.AverageDeleteContainer().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodGetContainerEacl).Set(float64(node.AverageGetContainerEACL().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodSetContainerEacl).Set(float64(node.AverageSetContainerEACL().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodEndpointInfo).Set(float64(node.AverageEndpointInfo().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodNetworkInfo).Set(float64(node.AverageNetworkInfo().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodPutObject).Set(float64(node.AveragePutObject().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodDeleteObject).Set(float64(node.AverageDeleteObject().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodGetObject).Set(float64(node.AverageGetObject().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodHeadObject).Set(float64(node.AverageHeadObject().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodRangeObject).Set(float64(node.AverageRangeObject().Milliseconds()))
	m.requestDuration.WithLabelValues(node.Address(), methodCreateSession).Set(float64(node.AverageCreateSession().Milliseconds()))
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
