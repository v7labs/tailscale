# WebSocket control transport

Set `TS_DEBUG_CONTROL_WS_CLIENT=true` to use the JS client's standard WebSocket
control transport in a native client. The native control transport remains the
default when this flag is absent.

The WebSocket transport requires verified HTTPS, the control subprotocol, and
the existing authenticated Noise handshake. It does not use the native IP/ACE
dial plan.

For relay connections over WebSockets, also build with `ts_debug_websockets`
and set `TS_DEBUG_DERP_WS_CLIENT=true`. The DERP flag does not change the control
transport.

```sh
CGO_ENABLED=0 go build -tags ts_debug_websockets -o tailscaled ./cmd/tailscaled
CGO_ENABLED=0 go build -tags ts_debug_websockets -o tailscale ./cmd/tailscale

TS_DEBUG_CONTROL_WS_CLIENT=true TS_DEBUG_DERP_WS_CLIENT=true \
  ./tailscaled --tun=userspace-networking --state=mem: \
  --socket=/tmp/tailscaled.sock --socks5-server=127.0.0.1:1055
```

Run the transport tests with:

```sh
go test -tags ts_debug_websockets ./control/controlhttp/...
```
