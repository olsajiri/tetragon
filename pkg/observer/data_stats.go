package observer

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Define a counter metric for data event statistics
	DataEventStats = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "data_event_stats",
		Help:        "Data event statistics. For internal use only.",
		ConstLabels: nil,
	}, []string{"event"})
)

type DataEventType int

const (
	DataEventReceived DataEventType = iota
	DataEventAdded
	DataEventAppended
	DataEventMatched
	DataEventNotMatched
)

var DataEventTypeStrings = map[DataEventType]string{
	DataEventReceived:   "Received",
	DataEventAdded:      "Added",
	DataEventAppended:   "Appended",
	DataEventMatched:    "Matched",
	DataEventNotMatched: "NotMatched",
}

// Increment a data event metric for an event type and location
func DataEventMetricInc(event DataEventType) {
	DataEventStats.WithLabelValues(DataEventTypeStrings[event]).Inc()
}
