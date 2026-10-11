package openai

import (
	"context"

	"github.com/gorilla/websocket"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// readResponsesWebsocketInput is the only downstream reader in duplex mode.
// The bounded queue backpressures clients instead of retaining unlimited input.
// readResponsesWebsocketInput reads the client's frames for the duplex path. A frame refuseFrame refuses (it has
// already answered the client) is dropped, so no consumer forwards it.
func readResponsesWebsocketInput(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, refuseFrame func([]byte) bool) <-chan cliproxyexecutor.WebsocketInput {
	input := make(chan cliproxyexecutor.WebsocketInput, 16)
	go func() {
		defer close(input)
		for {
			kind, payload, err := conn.ReadMessage()
			if err != nil {
				cancel()
				return
			}
			if kind != websocket.TextMessage && kind != websocket.BinaryMessage {
				continue
			}
			if refuseFrame != nil && refuseFrame(payload) {
				continue
			}
			select {
			case input <- cliproxyexecutor.WebsocketInput{Payload: payload}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return input
}
