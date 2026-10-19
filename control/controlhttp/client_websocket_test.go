// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package controlhttp

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func websocketTestDialer(t *testing.T, srv *httptest.Server, serverKey key.MachinePrivate) *Dialer {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return &Dialer{
		Hostname: host, HTTPSPort: port, HTTPPort: NoPort,
		MachineKey: key.NewMachine(), ControlKey: serverKey.Public(),
		ProtocolVersion: uint16(tailcfg.CurrentCapabilityVersion), ExtraRootCAs: roots,
	}
}

func TestWebsocketNoise(t *testing.T) {
	t.Setenv("TS_DEBUG_CONTROL_WS_CLIENT", "true")
	serverKey := key.NewMachine()
	served := make(chan error, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/ts2021" || r.Header.Get("Upgrade") != "websocket" || r.ProtoMajor != 1 {
			t.Errorf("unexpected WebSocket request: %s %s %s", r.Method, r.URL.Path, r.Proto)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := controlhttpserver.AcceptHTTP(ctx, w, r, serverKey, nil)
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 4)
		if _, err = io.ReadFull(conn, b); err == nil {
			_, err = conn.Write(b)
		}
		served <- err
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := websocketTestDialer(t, srv, serverKey).Dial(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer conn.Close()
	cancel() // A successful connection must survive handshake-context cancellation.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "ping" {
		t.Fatalf("Noise round trip = %q, %v", b, err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
}

func TestWebsocketRejectsUntrustedTLS(t *testing.T) {
	t.Setenv("TS_DEBUG_CONTROL_WS_CLIENT", "true")
	serverKey := key.NewMachine()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted TLS reached HTTP handler")
	}))
	defer srv.Close()
	d := websocketTestDialer(t, srv, serverKey)
	d.ExtraRootCAs = x509.NewCertPool()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := d.Dial(ctx); err == nil {
		c.Close()
		t.Fatal("accepted an untrusted TLS certificate")
	}
}

func TestWebsocketRejectsMissingSubprotocol(t *testing.T) {
	t.Setenv("TS_DEBUG_CONTROL_WS_CLIENT", "true")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err == nil {
			defer ws.CloseNow()
			ws.CloseRead(context.Background())
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := websocketTestDialer(t, srv, key.NewMachine()).Dial(ctx); err == nil {
		c.Close()
		t.Fatal("accepted an absent control subprotocol")
	} else if !strings.Contains(err.Error(), "control WebSocket subprotocol not negotiated") {
		t.Fatalf("expected subprotocol rejection, got %v", err)
	}
}

func TestWebsocketRejectsWrongNoiseKey(t *testing.T) {
	t.Setenv("TS_DEBUG_CONTROL_WS_CLIENT", "true")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := controlhttpserver.AcceptHTTP(ctx, w, r, key.NewMachine(), nil)
		if err == nil {
			c.Close()
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := websocketTestDialer(t, srv, key.NewMachine()).Dial(ctx); err == nil {
		c.Close()
		t.Fatal("accepted the wrong Noise server key")
	}
}

func TestWebsocketOptIn(t *testing.T) {
	t.Setenv("TS_DEBUG_CONTROL_WS_CLIENT", "false")
	t.Setenv("TS_FORCE_NOISE_443", "true")
	method := make(chan string, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method <- r.Method + ":" + r.Header.Get("Upgrade")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := websocketTestDialer(t, srv, key.NewMachine()).Dial(ctx)
	if err == nil {
		c.Close()
		t.Fatal("unexpected successful native dial")
	}
	if got := <-method; got != "POST:"+controlhttpcommon.UpgradeHeaderValue {
		t.Fatalf("default transport = %q", got)
	}
}
