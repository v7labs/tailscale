// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package controlhttp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/coder/websocket"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/net/netutil"
	"tailscale.com/net/wsconn"
)

// dialWebsocket uses the same control transport as the JS client.
// It requires verified HTTPS and does not use the native IP/ACE dial plan.
func (a *Dialer) dialWebsocket(ctx context.Context) (*ClientConn, error) {
	if a.HTTPSPort == NoPort {
		return nil, errors.New("control WebSockets require HTTPS")
	}
	init, cont, err := controlbase.ClientDeferred(a.MachineKey, a.ControlKey, a.ProtocolVersion)
	if err != nil {
		return nil, err
	}
	port := a.HTTPSPort
	if port == "" {
		port = "443"
	}
	u := &url.URL{
		Scheme: "wss",
		Host:   net.JoinHostPort(a.Hostname, port),
		Path:   serverUpgradePath,
		RawQuery: url.Values{
			controlhttpcommon.HandshakeHeaderName: {base64.StdEncoding.EncodeToString(init)},
		}.Encode(),
	}
	tr := netutil.NewDefaultTransport()
	defer tr.CloseIdleConnections()
	tr.Proxy = a.getProxyFunc()
	if a.Dialer != nil {
		tr.DialContext = a.Dialer
	}
	tr.ForceAttemptHTTP2 = false
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
	if a.ExtraRootCAs != nil {
		tr.TLSClientConfig.RootCAs = a.ExtraRootCAs
	}
	ws, _, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
		HTTPClient:      &http.Client{Transport: tr},
		Subprotocols:    []string{controlhttpcommon.UpgradeHeaderValue},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("control WebSocket upgrade: %w", err)
	}
	if ws.Subprotocol() != controlhttpcommon.UpgradeHeaderValue {
		ws.CloseNow()
		return nil, errors.New("control WebSocket subprotocol not negotiated")
	}
	// Only the handshake is bound to ctx. The caller owns the established conn.
	nc := wsconn.NetConn(context.Background(), ws, websocket.MessageBinary, net.JoinHostPort(a.Hostname, port))
	cb, err := cont(ctx, nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	a.logf("control: connected over WebSocket")
	return &ClientConn{Conn: cb}, nil
}
