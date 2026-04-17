package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rohits-web03/obscyra/internal/api/middleware"
	"github.com/rohits-web03/obscyra/internal/api/services"
	"github.com/rohits-web03/obscyra/internal/config"
	"github.com/rohits-web03/obscyra/internal/models"
	"github.com/rohits-web03/obscyra/internal/repositories"
	"github.com/rohits-web03/obscyra/internal/utils"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type RegisterInput struct {
	Username            string `json:"username"`
	Email               string `json:"email"`
	Password            string `json:"password"`
	PublicKey           string `json:"publicKey"`
	EncryptedPrivateKey string `json:"encryptedPrivateKey"`
}

type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// POST /api/v1/auth/sign-up
// Registers a new user with username, email, password, public key, and encrypted private key. Validates input and checks for existing username/email before creating the account. Returns success message on successful registration.
// @Summary User registration
// @Description Registers a new user with username, email, password, public key, and encrypted private key. Validates input and checks for existing username/email before creating the account. Returns success message on successful registration.
// @Tags Auth
// @Accept json
// @Produce json
// @Param registrationRequest body RegisterInput true "Registration request"
// @Success 201 {object} utils.Payload "User registered successfully"
// @Failure 400 {object} utils.Payload "Invalid input or user already exists"
// @Failure 500 {object} utils.Payload "Internal server error"
// @Router /api/v1/auth/sign-up [post]
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.JSONResponse(w, http.StatusMethodNotAllowed, utils.Payload{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	type Input struct {
		Username            string `json:"username"`
		Email               string `json:"email"`
		Password            string `json:"password"`
		PublicKey           string `json:"publicKey"`
		EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	}

	var input Input

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		utils.JSONResponse(w, http.StatusBadRequest, utils.Payload{
			Success: false,
			Message: "Invalid input",
		})
		return
	}

	if input.Email == "" || input.Username == "" || input.Password == "" {
		utils.JSONResponse(w, http.StatusBadRequest, utils.Payload{
			Success: false,
			Message: "Invalid input",
		})
		return
	}

	// Check if username already exists
	var existingUser models.User
	if err := repositories.DB.Where("username = ?", input.Username).First(&existingUser).Error; err == nil {
		utils.JSONResponse(w, http.StatusBadRequest, utils.Payload{
			Success: false,
			Message: "Username is already taken",
		})
		return
	}

	// Check if email already exists
	err := repositories.DB.Where("email = ?", input.Email).First(&existingUser).Error

	switch err {
	case nil: // email exists
		utils.JSONResponse(w, http.StatusBadRequest, utils.Payload{
			Success: false,
			Message: "User already exists with this email",
		})
		return

	case gorm.ErrRecordNotFound: // new user, create account
		hashedPassword, hashErr := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if hashErr != nil {
			utils.JSONResponse(w, http.StatusInternalServerError, utils.Payload{
				Success: false,
				Message: "Failed to hash password",
			})
			return
		}

		newUser := models.User{
			Username:            input.Username,
			Email:               input.Email,
			Password:            string(hashedPassword),
			PublicKey:           input.PublicKey,
			EncryptedPrivateKey: input.EncryptedPrivateKey,
		}

		if createErr := repositories.DB.Create(&newUser).Error; createErr != nil {
			utils.JSONResponse(w, http.StatusInternalServerError, utils.Payload{
				Success: false,
				Message: "Database insert failed",
			})
			return
		}

	default: // some other DB error
		utils.JSONResponse(w, http.StatusInternalServerError, utils.Payload{
			Success: false,
			Message: "Database query failed",
		})
		return
	}

	utils.JSONResponse(w, http.StatusCreated, utils.Payload{
		Success: true,
		Message: "User registered successfully",
	})
}

// JWT Claims struct
type Claims struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// POST /api/v1/auth/login
// Authenticates a user and issues a JWT token in an HTTP-only cookie. Expects JSON body with username and password. Validates credentials against the database, and on success, returns the user's public key and encrypted private key in the response.
// @Summary User login
// @Description Authenticates a user and issues a JWT token in an HTTP-only cookie. Expects JSON body with username and password. Validates credentials against the database, and on success, returns the user's public key and encrypted private key in the response.
// @Tags Auth
// @Accept json
// @Produce json
// @Param loginRequest body LoginInput true "Login request"
// @Success 200 {object} utils.Payload "Login successful, returns public and encrypted private keys"
// @Failure 400 {object} utils.Payload "Invalid input"
// @Failure 401 {object} utils.Payload "Invalid credentials"
// @Failure 500 {object} utils.Payload "Internal server error"
// @Router /api/v1/auth/login [post]
func LoginUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.JSONResponse(w, http.StatusMethodNotAllowed, utils.Payload{
			Success: false,
			Message: "Method not allowed",
		})
		return
	}

	// Parse request body
	var input LoginInput

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&input); err != nil {
		utils.JSONResponse(w, http.StatusBadRequest, utils.Payload{
			Success: false,
			Message: "Invalid input",
		})
		return
	}

	if input.Username == "" || input.Password == "" {
		utils.JSONResponse(w, http.StatusBadRequest, utils.Payload{
			Success: false,
			Message: "Invalid input",
		})
		return
	}

	var user models.User
	err := repositories.DB.Where("username = ?", input.Username).First(&user).Error
	switch err {
	case nil:
		// user found
	case gorm.ErrRecordNotFound:
		utils.JSONResponse(w, http.StatusUnauthorized, utils.Payload{
			Success: false,
			Message: "Invalid credentials",
		})
		return
	default:
		utils.JSONResponse(w, http.StatusInternalServerError, utils.Payload{
			Success: false,
			Message: "Database error",
		})
		return
	}

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		utils.JSONResponse(w, http.StatusUnauthorized, utils.Payload{
			Success: false,
			Message: "Invalid credentials",
		})
		return
	}

	// Load JWT secret
	secret := config.Envs.JWTSecret
	if secret == "" {
		utils.JSONResponse(w, http.StatusInternalServerError, utils.Payload{
			Success: false,
			Message: "No config found for JWT",
		})
		return
	}

	// Build JWT claims
	expiration := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:   user.ID.String(),
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Sign token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		utils.JSONResponse(w, http.StatusInternalServerError, utils.Payload{
			Success: false,
			Message: "Failed to create token",
		})
		return
	}

	// Cookie max-age
	maxAge := int(expiration.Unix() - time.Now().Unix())

	// Check if we’re in production
	isProd := config.Envs.Environment == "production"

	// SameSite cookie policy
	sameSite := http.SameSiteLaxMode
	if isProd {
		sameSite = http.SameSiteNoneMode
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   isProd,
		HttpOnly: true,
		SameSite: sameSite,
	})

	utils.JSONResponse(w, http.StatusOK, utils.Payload{
		Success: true,
		Message: "Login successful",
		Data: map[string]any{
			"private_key": user.EncryptedPrivateKey,
			"public_key":  user.PublicKey,
		},
	})
}

// GET /api/v1/me
// Fetches the current user's session info based on the JWT token. Returns user ID, username, and email. Requires authentication.
// @Summary Get current user session
// @Description Retrieves the current user's session information based on the JWT token. Returns user ID, username, and email. Requires authentication.
// @Tags Auth
// @Produce json
// @Success 200 {object} utils.Payload "User session retrieved successfully"
// @Failure 401 {object} utils.Payload "Unauthorized - invalid or missing token"
// @Router /api/v1/me [get]
func GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(string)
	if !ok || userID == "" {
		utils.JSONResponse(w, http.StatusUnauthorized, utils.Payload{
			Success: false,
			Message: "Unauthorized",
		})
		return
	}

	var user models.User
	if err := repositories.DB.First(&user, "id = ?", userID).Error; err != nil {
		utils.JSONResponse(w, http.StatusUnauthorized, utils.Payload{
			Success: false,
			Message: "Unauthorized",
		})
		return
	}

	utils.JSONResponse(w, http.StatusOK, utils.Payload{
		Success: true,
		Message: "User retrieved successfully",
		Data: map[string]any{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
	})
}

// POST /api/v1/logout
// Logs out the current user by clearing the JWT token cookie. Returns a success message on successful logout.
// @Summary User logout
// @Description Logs out the current user by clearing the JWT token cookie. Returns a success message on successful logout.
// @Tags Auth
// @Produce json
// @Success 200 {object} utils.Payload "Logged out successfully"
// @Failure 500 {object} utils.Payload "Internal server error"
// @Router /api/v1/logout [post]
func Logout(w http.ResponseWriter, r *http.Request) {
	isProd := config.Envs.Environment == "production"

	// Delete the token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "", // empty value
		Path:     "/",
		MaxAge:   -1, // maxAge < 0 deletes the cookie
		Secure:   isProd,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	utils.JSONResponse(w, http.StatusOK, utils.Payload{
		Success: true,
		Message: "Logged out successfully",
	})
}

// GET /api/v1/auth/google/login
// Initiates the Google OAuth login flow by generating a state parameter and redirecting the user to Google's OAuth consent screen.
// @Summary Initiate Google OAuth login
// @Description Initiates the Google OAuth login flow by generating a state parameter and redirecting the user to Google's OAuth consent screen.
// @Tags Auth
// @Produce json
// @Param redirect query string false "Optional redirect type (login or register)"
// @Success 302 "Redirects to Google OAuth consent screen"
// @Failure 500 {object} utils.Payload "Internal server error"
// @Router /api/v1/auth/google/login [get]
func HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	redirectType := r.URL.Query().Get("redirect") // "login" or "register"
	if redirectType == "" {
		redirectType = "login" // default
	}

	state, err := GenerateState(map[string]string{"flow": redirectType})
	if err != nil {
		http.Error(w, "Failed to generate OAuth state", http.StatusInternalServerError)
		return
	}

	url := services.GoogleOauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GET /api/v1/auth/google/callback
// Handles the callback from Google OAuth, exchanges the code for a token, retrieves user info, and either logs in or registers the user based on the flow type. Issues a JWT token and sets it in an HTTP-only cookie before redirecting the user to the appropriate frontend page.
// @Summary Handle Google OAuth callback
// @Description Handles the callback from Google OAuth, exchanges the code for a token, retrieves user info, and either logs in or registers the user based on the flow type. Issues a JWT token and sets it in an HTTP-only cookie before redirecting the user to the appropriate frontend page.
// @Tags Auth
// @Produce json
// @Success 302 "Redirects to frontend with login/register status"
// @Failure 400 {object} utils.Payload "Invalid OAuth state"
// @Failure 500 {object} utils.Payload "Internal server error"
// @Router /api/v1/auth/google/callback [get]
func HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	stateData, err := DecodeState(state)
	if err != nil {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}

	flowType := stateData["flow"] // "login" or "register"
	code := r.FormValue("code")

	token, err := services.GoogleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Code exchange failed", http.StatusInternalServerError)
		fmt.Println("Exchange error:", err)
		return
	}

	client := services.GoogleOauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	var googleUser struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}

	if err := json.Unmarshal(data, &googleUser); err != nil {
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}

	// Check if user exists
	var existingUser models.User
	err = repositories.DB.Where("email = ?", googleUser.Email).First(&existingUser).Error

	switch flowType {
	case "register":
		// If registering but user already exists
		if err == nil {
			http.Redirect(w, r, "http://localhost:5173/login?error=user_already_exists", http.StatusTemporaryRedirect)
			return
		}
		// Create new user
		newUser := models.User{
			Username:  googleUser.Name,
			Email:     googleUser.Email,
			Password:  "", // Google-authenticated
			CreatedAt: time.Now(),
		}
		if err := repositories.DB.Create(&newUser).Error; err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}
		existingUser = newUser

	case "login":
		// If logging in but user not found
		if err == gorm.ErrRecordNotFound {
			http.Redirect(w, r, "http://localhost:5173/register?error=user_not_found", http.StatusTemporaryRedirect)
			return
		} else if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
	}

	// Issue JWT
	secret := config.Envs.JWTSecret
	expiration := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:   existingUser.ID.String(),
		Username: existingUser.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		http.Error(w, "Failed to create JWT", http.StatusInternalServerError)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Path:     "/",
		MaxAge:   int((24 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   config.Envs.Environment == "production",
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect user
	redirectURL := "http://localhost:5173/share/send?status=success_login"
	if flowType == "register" {
		redirectURL = "http://localhost:5173/share/send?status=success_register"
	}

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}
