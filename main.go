package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
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

			fmt.Printf("Received %d bytes: %s\n", n, buffer[:n])
			header, sz, err := UnpackHeader(buffer[:n])
			if err != nil {
				fmt.Println("failed to parse header")
				conn.Close()
				return
			}
			fmt.Println(header)
			fmt.Println("DATA---")
			fmt.Println(string(UnmaskPayload(buffer[sz:sz+int(header.PayloadLength)], header.MaskingKey)))
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

// websocket Base Frame
// ```
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-------+-+-------------+-------------------------------+
//   |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//   |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//   |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//   | |1|2|3|       |K|             |                               |
//   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//   |     Extended payload length continued, if payload len == 127  |
//   + - - - - - - - - - - - - - - - +-------------------------------+
//   |                               |Masking-key, if MASK set to 1  |
//   +-------------------------------+-------------------------------+
//   | Masking-key (continued)       |          Payload Data         |
//   +-------------------------------- - - - - - - - - - - - - - - - +
//   :                     Payload Data continued ...                :
//   + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//   |                     Payload Data continued ...                |
//   +---------------------------------------------------------------+
// ```

// fin -> final fragment of a message -> first might also be last
// RSV1, RSV2, RSV3 -> usually zero unless some extension is negotiated
// opcode -> 4 bits ->
// mask -> is payload data masked (must be)
// Payload length -> 7, 7+16, 7+64
//  7 -> 0-125, if == 126 -> then next 16 bits are the payload length. elseif ==127 -> next 64 bits are the payload length
//  network byte order
// Masking key 0 or 4 bytes
// payload data -> extension data + Application Data

type WSFrameHeader struct {
	FIN           bool
	RSV1          bool
	RSV2          bool
	RSV3          bool
	OPCODE        uint8
	MASK          bool
	PayloadLength uint64
	MaskingKey    [4]byte
}

func UnpackHeader(data []byte) (WSFrameHeader, int, error) {
	var header WSFrameHeader

	if len(data) < 2 {
		return header, 0, errors.New("data too short for WebSocket frame header")
	}

	header.FIN = data[0]&0x80 != 0
	header.RSV1 = data[0]&0x40 != 0
	header.RSV2 = data[0]&0x20 != 0
	header.RSV3 = data[0]&0x10 != 0
	header.OPCODE = data[0] & 0x0F

	header.MASK = data[1]&0x80 != 0
	payloadLen := data[1] & 0x7F

	headerSize := 2
	switch payloadLen {
	case 126:
		if len(data) < 4 {
			return header, 0, errors.New("data too short for extended payload length")
		}
		header.PayloadLength = uint64(binary.BigEndian.Uint16(data[2:4]))
		headerSize += 2
	case 127:
		if len(data) < 10 {
			return header, 0, errors.New("data too short for extended payload length")
		}
		header.PayloadLength = binary.BigEndian.Uint64(data[2:10])
		headerSize += 8
	default:
		header.PayloadLength = uint64(payloadLen)
	}

	if header.MASK {
		headerSize += 4
		if len(data) < headerSize {
			return header, 0, errors.New("data too short for masking key")
		}
		copy(header.MaskingKey[:], data[headerSize-4:headerSize])
	}

	return header, headerSize, nil
}

func (h WSFrameHeader) String() string {
	return fmt.Sprintf(
		"FIN: %t, RSV1: %t, RSV2: %t, RSV3: %t, OPCODE: %d, MASK: %t, PayloadLength: %d, MaskingKey: %x",
		h.FIN,
		h.RSV1,
		h.RSV2,
		h.RSV3,
		h.OPCODE,
		h.MASK,
		h.PayloadLength,
		h.MaskingKey,
	)
}

func UnmaskPayload(data []byte, maskingKey [4]byte) []byte {
	unmasked := make([]byte, len(data))
	for i, b := range data {
		unmasked[i] = b ^ maskingKey[i%4]
	}
	return unmasked
}
