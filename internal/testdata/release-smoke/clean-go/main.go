package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		db, err := sql.Open("sqlite3", ":memory:")
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer db.Close()
		rows, err := db.Query("SELECT * FROM users WHERE name = ?", name)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		fmt.Fprintf(w, "ok")
	})
	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := server.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
		fmt.Printf("server error: %v\n", err)
	}
}
