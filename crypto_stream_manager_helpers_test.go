package quic

// newCryptoStreamFixture retains explicit stream fixtures with one manager owner.
func newCryptoStreamFixture(initial *initialCryptoStream, handshake, application *cryptoStream) *cryptoStreamManager {
	return &cryptoStreamManager{initialStream: initial, handshakeStream: handshake, oneRTTStream: application}
}
