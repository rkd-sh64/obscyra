package api

import (
	"fmt"
	"log"
	"net/http"

	_ "github.com/rohits-web03/obscyra/docs"
	httpSwagger "github.com/swaggo/http-swagger"

	"github.com/rohits-web03/obscyra/internal/api/handlers"
	"github.com/rohits-web03/obscyra/internal/api/middleware"
	"github.com/rohits-web03/obscyra/internal/config"
	"github.com/rs/cors"
)

func SetupRouter() http.Handler {
	mainMux := http.NewServeMux()
	c := cors.New(config.Envs.CorsConfig)

	// ---------- PUBLIC ROUTES ----------
	mainMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})

	mainMux.HandleFunc("/docs/", httpSwagger.WrapHandler)

	authMux := http.NewServeMux()
	authMux.HandleFunc("/sign-up", handlers.RegisterUser)
	authMux.HandleFunc("/login", handlers.LoginUser)
	authMux.HandleFunc("/google/login", handlers.HandleGoogleLogin)
	authMux.HandleFunc("/google/callback", handlers.HandleGoogleCallback)

	mainMux.Handle("/api/v1/auth/",
		http.StripPrefix("/api/v1/auth", authMux),
	)

	// ---------- PROTECTED ROUTES ----------
	protectedMux := http.NewServeMux()

	fileMux := http.NewServeMux()
	fileMux.HandleFunc("/presign", handlers.PresignUpload)
	fileMux.HandleFunc("/complete", handlers.CompleteUpload)

	shareMux := http.NewServeMux()
	shareMux.HandleFunc("/{token}", handlers.GetSharedFiles)
	shareMux.HandleFunc("/{token}/presign-download/{index}", handlers.PresignDownload)

	protectedMux.Handle("/files/",
		http.StripPrefix("/files", fileMux),
	)
	protectedMux.Handle("/share/",
		http.StripPrefix("/share", shareMux),
	)

	protectedMux.HandleFunc("/me", handlers.GetCurrentUser)
	protectedMux.HandleFunc("/logout", handlers.Logout)

	mainMux.Handle("/api/v1/",
		http.StripPrefix(
			"/api/v1",
			middleware.AuthMiddleware(protectedMux),
		),
	)

	log.Println("Router initialized")
	handler := c.Handler(mainMux)
	handler = middleware.Logger(handler)
	return handler
}
