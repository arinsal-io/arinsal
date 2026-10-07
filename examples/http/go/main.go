package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
)

type item struct {
	ID    int     `json:"id"`
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

type workResponse struct {
	N     int             `json:"n"`
	Fib   json.RawMessage `json:"fib"`
	Items []item          `json:"items"`
}

func fib(n int) json.RawMessage {
	a, b := big.NewInt(0), big.NewInt(1)
	for i := 0; i < n; i++ {
		a, b = b, new(big.Int).Add(a, b)
	}
	return json.RawMessage(a.String())
}

func work(w http.ResponseWriter, r *http.Request) {
	n := 20
	if value := r.URL.Query().Get("n"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			http.Error(w, "invalid n", http.StatusBadRequest)
			return
		}
		n = parsed
	}
	if n > 1000 {
		n = 1000
	}
	items := make([]item, n)
	for i := range items {
		items[i] = item{ID: i, Name: fmt.Sprintf("item-%d", i), Score: float64(i) * 1.5}
	}
	w.Header().Set("Content-Type", "application/json")
	body, _ := json.Marshal(workResponse{N: n, Fib: fib(n), Items: items})
	_, _ = w.Write(body)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /plaintext", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Hello, World!"))
	})
	mux.HandleFunc("GET /json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"Hello, World!"}`))
	})
	mux.HandleFunc("GET /work", work)
	mux.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		var value any
		if err := json.NewDecoder(r.Body).Decode(&value); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(value)
		_, _ = w.Write(body)
	})
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, mux))
}
