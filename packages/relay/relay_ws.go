package relay

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

const pendingAuthTTL = 30 * time.Second

type pendingWSAuth struct {
	gatewayID   string
	gatewayName string
	expiresAt   time.Time
}

type wsAuthStore struct {
	mu      sync.Mutex
	pending map[string]*pendingWSAuth
}

func newWSAuthStore() *wsAuthStore {
	return &wsAuthStore{pending: make(map[string]*pendingWSAuth)}
}

func (s *wsAuthStore) store(id string, auth *pendingWSAuth) {
	s.mu.Lock()
	s.pending[id] = auth
	s.mu.Unlock()
}

func (s *wsAuthStore) consume(id string) (*pendingWSAuth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	auth, ok := s.pending[id]
	if !ok {
		return nil, false
	}
	delete(s.pending, id)

	if time.Now().After(auth.expiresAt) {
		return nil, false
	}

	return auth, true
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(req *http.Request) bool { return true },
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if req.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, req)
	})
}

func (r *Relay) startWSServer() {
	listener, err := net.Listen("tcp", ":"+r.config.WSPort)
	if err != nil {
		log.Fatal().Msgf("Failed to start WebSocket server: %v", err)
	}
	r.wsListener = listener

	authStore := newWSAuthStore()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws/authenticate", r.handleWSAuthenticate(authStore))
	mux.HandleFunc("/ws", r.handleWSUpgrade(authStore))

	server := &http.Server{Handler: corsMiddleware(mux)}
	log.Info().Msgf("WebSocket server listening on :%s for browser clients", r.config.WSPort)

	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		log.Error().Msgf("WebSocket server error: %v", err)
	}
}

func (r *Relay) handleWSAuthenticate(authStore *wsAuthStore) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(req.Body, 8192))
		if err != nil || len(body) == 0 {
			http.Error(w, "missing certificate", http.StatusBadRequest)
			return
		}

		block, _ := pem.Decode(body)
		if block == nil {
			http.Error(w, "invalid PEM", http.StatusBadRequest)
			return
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			http.Error(w, "invalid certificate", http.StatusBadRequest)
			return
		}

		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:     r.tlsConfig.ClientCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			log.Debug().Msgf("WebSocket client certificate verification failed: %v", err)
			http.Error(w, "certificate verification failed", http.StatusUnauthorized)
			return
		}

		gatewayID := cert.Subject.CommonName
		if gatewayID == "" {
			http.Error(w, "missing gateway ID in certificate", http.StatusBadRequest)
			return
		}

		var gatewayName string
		for _, ext := range cert.Extensions {
			if ext.Id.String() == RELAY_CONNECTING_GATEWAY_INFO_OID {
				var info ConnectingGatewayInfo
				if err := json.Unmarshal(ext.Value, &info); err != nil {
					log.Warn().Msgf("Failed to unmarshal gateway info from WS auth cert: %v", err)
				} else {
					gatewayName = info.Name
				}
			}
		}

		idBytes := make([]byte, 16)
		if _, err := rand.Read(idBytes); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		connectionID := hex.EncodeToString(idBytes)

		authStore.store(connectionID, &pendingWSAuth{
			gatewayID:   gatewayID,
			gatewayName: gatewayName,
			expiresAt:   time.Now().Add(pendingAuthTTL),
		})

		log.Info().Msgf("WebSocket auth successful for gateway %s (%s), connectionId=%s", gatewayName, gatewayID, connectionID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"connectionId": connectionID})
	}
}

func (r *Relay) handleWSUpgrade(authStore *wsAuthStore) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		connectionID := req.URL.Query().Get("connectionId")
		if connectionID == "" {
			http.Error(w, "missing connectionId", http.StatusUnauthorized)
			return
		}

		auth, ok := authStore.consume(connectionID)
		if !ok {
			http.Error(w, "invalid or expired connectionId", http.StatusUnauthorized)
			return
		}

		wsConn, err := wsUpgrader.Upgrade(w, req, nil)
		if err != nil {
			log.Error().Msgf("WebSocket upgrade failed: %v", err)
			return
		}

		r.handleWSClient(wsConn, auth.gatewayID, auth.gatewayName)
	}
}

func (r *Relay) handleWSClient(wsConn *websocket.Conn, gatewayID string, gatewayName string) {
	defer wsConn.Close()

	log.Info().Msgf("WebSocket client connected for gateway %s (%s)", gatewayName, gatewayID)

	r.mu.RLock()
	sshConn, exists := r.tunnels[gatewayID]
	r.mu.RUnlock()

	if !exists {
		log.Warn().Msgf("Gateway '%s' (%s) not connected (WebSocket client)", gatewayName, gatewayID)
		wsConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "gateway not connected"))
		return
	}

	channel, _, err := sshConn.OpenChannel("direct-tcpip", nil)
	if err != nil {
		log.Error().Msgf("Failed to open SSH channel to gateway %s (%s): %v", gatewayName, gatewayID, err)
		wsConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "gateway connection failed"))
		return
	}
	defer channel.Close()

	done := make(chan struct{}, 1)

	// WS -> SSH
	go func() {
		defer func() {
			done <- struct{}{}
		}()
		for {
			msgType, msg, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			if msgType != websocket.BinaryMessage {
				continue
			}
			if _, err := channel.Write(msg); err != nil {
				return
			}
		}
	}()

	// SSH -> WS
	go func() {
		defer func() {
			done <- struct{}{}
		}()
		buf := make([]byte, 32*1024)
		for {
			n, err := channel.Read(buf)
			if n > 0 {
				if writeErr := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	<-done
	log.Info().Msgf("WebSocket client disconnected for gateway %s (%s)", gatewayName, gatewayID)
}
