package quic

import "github.com/alvarorichard/enetx-quic-go/internal/ackhandler"

// StreamLossInfo describes lost STREAM packet ACK metadata supplied to
// ClientHandshake.StreamLossRetention. Its counters are transport observations.
type StreamLossInfo = ackhandler.StreamLossInfo
