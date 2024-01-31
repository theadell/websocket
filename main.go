package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

func main() {

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// check headers to upgrade connection

		upgradeHeader := r.Header.Get("Upgrade")
		ConnectionHeader := r.Header.Get("Connection")
		SecWebSocketKeyHeader := r.Header.Get("Sec-WebSocket-Key")
		// SecWebSocketVersionHeader := r.Header.Get("Sec-WebSocket-Version")

		fmt.Println("---REQ HEADERS---")
		for k, v := range r.Header {
			fmt.Printf("%s: %s \n", k, v)
		}
		fmt.Println("----------------")
		if !strings.EqualFold(upgradeHeader, "websocket") || !strings.EqualFold(ConnectionHeader, "Upgrade") {
			log.Println("not a websocket handshake")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// handshake
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", computeWebSocketAcceptKey(SecWebSocketKeyHeader))
		w.WriteHeader(http.StatusSwitchingProtocols)

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			fmt.Println("Hijacking didn't work")
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			fmt.Println("failed to hijack connection")
		}
		buffer := make([]byte, 1024)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					fmt.Println("Error reading:", err)
				}
				break
			}

			fmt.Printf("Received: %s\n", buffer[:n])
		}
		conn.Close()

	})

	http.ListenAndServe("127.0.0.1:8080", nil)

}

func computeWebSocketAcceptKey(clientKey string) string {
	guid := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	hash := sha1.New()
	hash.Write([]byte(clientKey + guid))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}
