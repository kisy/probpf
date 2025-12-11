package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kisy/probpf/pkg/model"
	"github.com/kisy/probpf/pkg/stats"
)

//go:embed clients.html
var htmlContent []byte

//go:embed client.html
var clientHtmlContent []byte

//go:embed static
var staticFiles embed.FS

type Server struct {
	agg *stats.Aggregator
}

func NewServer(agg *stats.Aggregator) *Server {
	return &Server{agg: agg}
}

func (s *Server) RegisterHandlers() {
	http.HandleFunc("/clients", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(htmlContent)
	})

	http.HandleFunc("/client", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write(clientHtmlContent)
	})

	http.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	http.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := struct {
			StartTime time.Time           `json:"start_time"`
			Global    model.GlobalStats   `json:"global"`
			Clients   []model.ClientStats `json:"clients"`
		}{
			StartTime: s.agg.GetStartTime(),
			Global:    s.agg.GetGlobalStats(),
			Clients:   s.agg.GetClients(),
		}
		json.NewEncoder(w).Encode(response)
	})

	http.HandleFunc("/api/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := s.agg.Reset(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	http.HandleFunc("/api/client", func(w http.ResponseWriter, r *http.Request) {
		mac := r.URL.Query().Get("mac")
		if mac == "" {
			http.Error(w, "Missing mac parameter", http.StatusBadRequest)
			return
		}
		mac = strings.TrimSpace(strings.ToLower(mac))
		w.Header().Set("Content-Type", "application/json")
		response := struct {
			Client *model.ClientStats `json:"client"`
			Flows  []model.FlowDetail `json:"flows"`
		}{
			Client: s.agg.GetClientWithSession(mac),
			Flows:  s.agg.GetFlowsByMAC(mac),
		}
		json.NewEncoder(w).Encode(response)
	})

	http.HandleFunc("/api/client/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mac := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mac")))
		fmt.Printf("API: Reset Client %s\n", mac)
		if err := s.agg.ResetClientByMAC(mac); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/api/client/reset_session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mac := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mac")))
		fmt.Printf("API: Reset Session %s\n", mac)
		if err := s.agg.ResetSessionByMAC(mac); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte("OK"))
	})
}
