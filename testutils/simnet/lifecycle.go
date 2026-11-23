package simnet

// Start is retained for callers that explicitly started older simulated networks.
// NewEndpoint now starts every link immediately; no second start is required.
func (n *Simnet) Start() error { return nil }
