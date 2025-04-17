package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	apiSubsystem = "api"
)

// ApiMetrics contains metric definitions for API.
type ApiMetrics struct {
	GetBalanceDuration               prometheus.Histogram
	AuthDuration                     prometheus.Histogram
	FormBinaryBearerDuration         prometheus.Histogram
	ListContainersDuration           prometheus.Histogram
	PutContainerDuration             prometheus.Histogram
	PostContainerDuration            prometheus.Histogram
	DeleteContainerDuration          prometheus.Histogram
	GetContainerDuration             prometheus.Histogram
	GetContainerEACLDuration         prometheus.Histogram
	PutContainerEACLDuration         prometheus.Histogram
	GetContainerObjectDuration       prometheus.Histogram
	HeadContainerObjectDuration      prometheus.Histogram
	GetByAttributeDuration           prometheus.Histogram
	HeadByAttributeDuration          prometheus.Histogram
	GetNetworkInfoDuration           prometheus.Histogram
	PutObjectDuration                prometheus.Histogram
	NewUploadContainerObjectDuration prometheus.Histogram
	NewGetByAttributeDuration        prometheus.Histogram
	NewHeadByAttributeDuration       prometheus.Histogram
	NewGetContainerObjectDuration    prometheus.Histogram
	NewHeadContainerObjectDuration   prometheus.Histogram
	SearchObjectsDuration            prometheus.Histogram
	DeleteObjectDuration             prometheus.Histogram
	GetObjectInfoDuration            prometheus.Histogram
	UploadContainerObjectDuration    prometheus.Histogram
	V2SearchObjectsDuration          prometheus.Histogram
}

// Elapsed calculates and store method execution time for corresponding histogram.
func Elapsed(h prometheus.Histogram) func() {
	t := time.Now()

	return func() {
		h.Observe(time.Since(t).Seconds())
	}
}

// NewApiMetrics is a constructor ApiMetrics.
func NewApiMetrics() *ApiMetrics {
	m := &ApiMetrics{
		GetBalanceDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "get_balance_duration",
			Help:      "Get balance request handling time",
		}),
		AuthDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "auth_duration",
			Help:      "Auth request handling time",
		}),

		FormBinaryBearerDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "form_binary_bearer_duration",
			Help:      "Form binary bearer request handling time",
		}),
		ListContainersDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "list_containers_duration",
			Help:      "List containers request handling time",
		}),
		PutContainerDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "put_container_duration",
			Help:      "Put container request handling time",
		}),
		PostContainerDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "post_container_duration",
			Help:      "Post container request handling time",
		}),
		DeleteContainerDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "delete_container_duration",
			Help:      "Delete container request handling time",
		}),
		GetContainerDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "get_container_duration",
			Help:      "Get container request handling time",
		}),
		GetContainerEACLDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "get_container_eacl_duration",
			Help:      "Get container eacl request handling time",
		}),
		PutContainerEACLDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "put_container_eacl_duration",
			Help:      "Put container eacl request handling time",
		}),
		GetContainerObjectDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "get_container_object_duration",
			Help:      "Get container object request handling time",
		}),
		HeadContainerObjectDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "head_container_object_duration",
			Help:      "Head container object request handling time",
		}),
		GetByAttributeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "get_by_attribute_duration",
			Help:      "Get by attribute request handling time",
		}),
		HeadByAttributeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "head_by_attribute_duration",
			Help:      "Head by attribute request handling time",
		}),
		GetNetworkInfoDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "get_network_info_duration",
			Help:      "Get network info duration request handling time",
		}),
		PutObjectDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "put_object_duration",
			Help:      "Put object request handling time",
		}),
		NewUploadContainerObjectDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "new_upload_container_object_duration",
			Help:      "New upload container object request handling time",
		}),
		NewGetByAttributeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "new_get_by_attribute_duration",
			Help:      "New get by attribute request handling time",
		}),
		NewHeadByAttributeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "new_head_by_attribute_duration",
			Help:      "New head by attribute request handling time",
		}),
		NewGetContainerObjectDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "new_get_container_object_duration",
			Help:      "New get container object request handling time",
		}),
		NewHeadContainerObjectDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "new_head_container_object_duration",
			Help:      "New head container object request handling time",
		}),
		SearchObjectsDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "search_objects_duration",
			Help:      "search objects request handling time",
		}),
		DeleteObjectDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "delete_object_duration",
			Help:      "Delete object request handling time",
		}),
		GetObjectInfoDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "get_object_info_duration",
			Help:      "Get object info request handling time",
		}),
		UploadContainerObjectDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "upload_container_object_duration",
			Help:      "Upload container object request handling time",
		}),
		V2SearchObjectsDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: apiSubsystem,
			Name:      "v2_search_objects_duration",
			Help:      "V2 search objects request handling time",
		}),
	}

	m.register()

	return m
}

func (m ApiMetrics) register() {
	prometheus.MustRegister(m.GetBalanceDuration)
	prometheus.MustRegister(m.AuthDuration)
	prometheus.MustRegister(m.FormBinaryBearerDuration)
	prometheus.MustRegister(m.ListContainersDuration)
	prometheus.MustRegister(m.PutContainerDuration)
	prometheus.MustRegister(m.PostContainerDuration)
	prometheus.MustRegister(m.DeleteContainerDuration)
	prometheus.MustRegister(m.GetContainerDuration)
	prometheus.MustRegister(m.GetContainerEACLDuration)
	prometheus.MustRegister(m.PutContainerEACLDuration)
	prometheus.MustRegister(m.GetContainerObjectDuration)
	prometheus.MustRegister(m.HeadContainerObjectDuration)
	prometheus.MustRegister(m.GetByAttributeDuration)
	prometheus.MustRegister(m.HeadByAttributeDuration)
	prometheus.MustRegister(m.GetNetworkInfoDuration)
	prometheus.MustRegister(m.PutObjectDuration)
	prometheus.MustRegister(m.NewUploadContainerObjectDuration)
	prometheus.MustRegister(m.NewGetByAttributeDuration)
	prometheus.MustRegister(m.NewHeadByAttributeDuration)
	prometheus.MustRegister(m.NewGetContainerObjectDuration)
	prometheus.MustRegister(m.NewHeadContainerObjectDuration)
	prometheus.MustRegister(m.SearchObjectsDuration)
	prometheus.MustRegister(m.DeleteObjectDuration)
	prometheus.MustRegister(m.GetObjectInfoDuration)
	prometheus.MustRegister(m.UploadContainerObjectDuration)
	prometheus.MustRegister(m.V2SearchObjectsDuration)
}
