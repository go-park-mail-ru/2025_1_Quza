package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-park-mail-ru/2025_1_Quza/platform/pkg/logger"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

var validate *validator.Validate

func jsonError(w http.ResponseWriter, statusCode int, errMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": errMsg,
	})
}

func jsonSuccess(w http.ResponseWriter, statusCode int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": msg,
	})
}

type UploadCredentials struct {
	ProjName string `json:"projName"`
	Data     string `json:"data"`
}
type FileItem struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Content    string   `json:"content"`
	Data       []string `json:"data"`
	CreateTime string   `json:"create_time"`
	UpdateTime string   `json:"update_time"`
}

var files = []FileItem{
	{
		ID:      "codes1",
		Title:   "Back Code 1",
		Content: "0 mb",
		Data: []string{
			"Добро пожаловать! Это основное место работы.",
			"Здесь можно добавлять блоки, а в будущем еще изменять и запускать",
		},
		CreateTime: time.Now().Format(time.RFC3339),
		UpdateTime: time.Now().Format(time.RFC3339),
	},
	//{
	//	ID:         "codes2",
	//	Title:      "Back Code 2",
	//	Content:    "0 mb",
	//	Data:       []string{"BackString1", "BackString2", "BackString3"},
	//	CreateTime: time.Now().Format(time.RFC3339),
	//	UpdateTime: time.Now().Format(time.RFC3339),
	//},
}

var mu sync.RWMutex

type SignUpRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=8,lte=254"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,gte=0,lte=254"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CustomClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type Session struct {
	Email        string
	RefreshToken string
	ExpiresAt    time.Time
}

var users sync.Map
var sessions sync.Map
var secretKey []byte

const (
	accessTokenTTL  = time.Minute * 5
	refreshTokenTTL = time.Hour * 24
)

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	var req SignUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("HTTP", "handleSignUp: ошибка декодирования JSON: %v", err)
		jsonError(w, http.StatusBadRequest, "Неверный формат JSON")
		return
	}

	if err := validate.Struct(req); err != nil {
		logger.Error("HTTP", "handleSignUp: ошибка валидации: %v", err)
		jsonError(w, http.StatusBadRequest, "Ошибка валидации")
		return
	}

	if _, exists := users.Load(req.Email); exists {
		logger.Info("HTTP", "handleSignUp: попытка регистрации уже существующего пользователя %s", req.Email)
		jsonError(w, http.StatusBadRequest, "Пользователь с таким email уже существует")
		return
	}

	user := User{
		Email:    req.Email,
		Password: req.Password,
	}
	users.Store(user.Email, user)

	logger.Info("HTTP", "handleSignUp: пользователь %s успешно зарегистрирован", user.Email)
	jsonSuccess(w, http.StatusCreated, fmt.Sprintf("Пользователь %s успешно зарегистрирован", user.Email))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("HTTP", "handleLogin: ошибка декодирования JSON: %v", err)
		jsonError(w, http.StatusBadRequest, "Неверный формат JSON")
		return
	}

	if err := validate.Struct(req); err != nil {
		logger.Error("HTTP", "handleLogin: ошибка валидации: %v", err)
		jsonError(w, http.StatusBadRequest, "Ошибка валидации")
		return
	}

	user, ok := users.Load(req.Email)
	if !ok {
		logger.Info("HTTP", "handleLogin: пользователь %s не найден", req.Email)
		jsonError(w, http.StatusUnauthorized, "Пользователь не найден")
		return
	}

	us, ok := user.(User)
	if !ok {
		logger.Error("HTTP", "handleLogin: ошибка приведения типа пользователя")
		jsonError(w, http.StatusInternalServerError, "Ошибка при конвертации пользователя")
		return
	}

	if us.Password != req.Password {
		logger.Info("HTTP", "handleLogin: неверный пароль для пользователя %s", req.Email)
		jsonError(w, http.StatusUnauthorized, "Неверный пароль")
		return
	}

	accessToken, err := generateJWT(us.Email, accessTokenTTL)
	if err != nil {
		logger.Error("HTTP", "handleLogin: не удалось сгенерировать access-токен: %v", err)
		jsonError(w, http.StatusInternalServerError, "Не удалось сгенерировать access-токен")
		return
	}

	refreshToken, err := generateJWT(us.Email, refreshTokenTTL)
	if err != nil {
		logger.Error("HTTP", "handleLogin: не удалось сгенерировать refresh-токен: %v", err)
		jsonError(w, http.StatusInternalServerError, "Не удалось сгенерировать refresh-токен")
		return
	}

	sessions.Store(refreshToken, Session{
		Email:        us.Email,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(refreshTokenTTL),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		Expires:  time.Now().Add(accessTokenTTL),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		Expires:  time.Now().Add(refreshTokenTTL),
		HttpOnly: true,
	})

	logger.Info("HTTP", "handleLogin: пользователь %s успешно вошел в систему", req.Email)
	jsonSuccess(w, http.StatusOK, "Логин успешен")
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshCookie, err := r.Cookie("refresh_token")
	if err != nil {
		logger.Error("HTTP", "handleRefresh: refresh-токен не найден в cookies: %v", err)
		jsonError(w, http.StatusUnauthorized, "refresh-токен не найден")
		return
	}

	var req RefreshRequest
	req.RefreshToken = refreshCookie.Value

	if err := validate.Struct(req); err != nil {
		logger.Error("HTTP", "handleRefresh: ошибка валидации: %v", err)
		jsonError(w, http.StatusBadRequest, "Ошибка валидации")
		return
	}

	session, ok := sessions.Load(req.RefreshToken)
	if !ok {
		logger.Info("HTTP", "handleRefresh: refresh-токен %s не найден или отозван", req.RefreshToken)
		jsonError(w, http.StatusUnauthorized, "refresh-токен не найден или отозван")
		return
	}

	formatSession, ok := session.(Session)
	if !ok {
		logger.Error("HTTP", "handleRefresh: ошибка приведения типа сессии")
		jsonError(w, http.StatusInternalServerError, "Ошибка при конвертации сессии")
		return
	}

	if time.Now().After(formatSession.ExpiresAt) {
		sessions.Delete(req.RefreshToken)
		logger.Info("HTTP", "handleRefresh: refresh-токен %s просрочен", req.RefreshToken)
		jsonError(w, http.StatusUnauthorized, "refresh-токен просрочен")
		return
	}

	claims, err := parseJWT(req.RefreshToken)
	if err != nil {
		sessions.Delete(req.RefreshToken)
		logger.Error("HTTP", "handleRefresh: невалидный refresh-токен: %v", err)
		jsonError(w, http.StatusUnauthorized, "refresh-токен невалиден")
		return
	}

	newAccess, err := generateJWT(claims.Email, accessTokenTTL)
	if err != nil {
		logger.Error("HTTP", "handleRefresh: ошибка генерации нового access-токена: %v", err)
		jsonError(w, http.StatusInternalServerError, "Ошибка генерации нового access-токена")
		return
	}
	newRefresh, err := generateJWT(claims.Email, refreshTokenTTL)
	if err != nil {
		logger.Error("HTTP", "handleRefresh: ошибка генерации нового refresh-токена: %v", err)
		jsonError(w, http.StatusInternalServerError, "Ошибка генерации нового refresh-токена")
		return
	}

	sessions.Delete(req.RefreshToken)
	sessions.Store(newRefresh, Session{
		Email:        claims.Email,
		RefreshToken: newRefresh,
		ExpiresAt:    time.Now().Add(refreshTokenTTL),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    newAccess,
		Path:     "/",
		Expires:  time.Now().Add(accessTokenTTL),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    newRefresh,
		Path:     "/",
		Expires:  time.Now().Add(refreshTokenTTL),
		HttpOnly: true,
	})

	logger.Info("HTTP", "handleRefresh: refresh-токен успешно обновлен для пользователя %s", claims.Email)
	jsonSuccess(w, http.StatusOK, "Токены обновлены")
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	refreshCookie, err := r.Cookie("refresh_token")
	if err != nil {
		logger.Info("HTTP", "handleLogout: refresh-токен не найден в cookies")
		jsonError(w, http.StatusUnauthorized, "refresh-токен не найден")
		return
	}

	var req RefreshRequest
	req.RefreshToken = refreshCookie.Value

	if err := validate.Struct(req); err != nil {
		logger.Error("HTTP", "handleLogout: ошибка валидации: %v", err)
		jsonError(w, http.StatusBadRequest, "Ошибка валидации")
		return
	}

	if _, ok := sessions.Load(req.RefreshToken); !ok {
		logger.Info("HTTP", "handleLogout: refresh-токен %s не найден или уже отозван", req.RefreshToken)
		jsonError(w, http.StatusUnauthorized, "refresh-токен не найден или уже отозван")
		return
	}

	sessions.Delete(req.RefreshToken)

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
	})

	logger.Info("HTTP", "handleLogout: пользователь успешно вышел из системы")
	jsonSuccess(w, http.StatusOK, "Вы успешно вышли из системы")
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	email, err := validateAccessToken(r)
	if err != nil {
		logger.Info("HTTP", "handleProfile: ошибка валидации access-токена: %v", err)
		jsonError(w, http.StatusUnauthorized, err.Error())
		return
	}

	user, ok := users.Load(email)
	if !ok {
		logger.Info("HTTP", "handleProfile: пользователь %s не найден", email)
		jsonError(w, http.StatusNotFound, "Пользователь не найден")
		return
	}

	usFormat, ok := user.(User)
	if !ok {
		logger.Error("HTTP", "handleProfile: ошибка приведения типа пользователя")
		jsonError(w, http.StatusInternalServerError, "Ошибка при конвертации пользователя")
		return
	}

	logger.Info("HTTP", "handleProfile: профиль пользователя %s запрошен", email)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"name":  usFormat.Name,
		"email": usFormat.Email,
	}); err != nil {
		logger.Error("HTTP", "handleProfile: ошибка формирования JSON-ответа: %v", err)
		jsonError(w, http.StatusInternalServerError, "Ошибка при формировании JSON-ответа")
		return
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	logger.Info("HTTP", "handleUpload: входящий запрос на /file (POST)")
	var creds UploadCredentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		logger.Info("HTTP", "handleUpload: ошибка парсинга JSON — "+err.Error())
		jsonError(w, http.StatusBadRequest, "Bad request: "+err.Error())
		return
	}
	logger.Info("HTTP", "handleUpload: успешно распарсили JSON")

	mu.Lock()
	defer mu.Unlock()

	logger.Info("HTTP", "handleUpload: ищем FileItem с ID = "+creds.ProjName)
	found := false
	for i := range files {
		if files[i].ID == creds.ProjName {
			files[i].Data = append(files[i].Data, creds.Data)
			files[i].UpdateTime = time.Now().Format(time.RFC3339)
			logger.Info("HTTP", "handleUpload: успешно добавили Data в FileItem с ID = "+creds.ProjName)
			found = true
			break
		}
	}
	if !found {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("FileItem с ID=%s не найден", creds.ProjName))
		return
	}

	jsonSuccess(w, http.StatusOK, "success")
	logger.Info("HTTP", "handleUpload: ответ отдан, статус 200")
}

func handleGet(w http.ResponseWriter, _ *http.Request) {
	logger.Info("HTTP", "handleGet: входящий запрос на /file (GET)")
	w.Header().Set("Content-Type", "application/json")

	mu.RLock()
	defer mu.RUnlock()

	if err := json.NewEncoder(w).Encode(files); err != nil {
		logger.Info("HTTP", "handleGet: ошибка при кодировании JSON — "+err.Error())
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	logger.Info("HTTP", "handleGet: успешно вернули массив files")
}

func validateAccessToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	var tokenStr string
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			tokenStr = parts[1]
		}
	}

	if tokenStr == "" {
		cookie, err := r.Cookie("access_token")
		if err != nil {
			logger.Info("HTTP", "validateAccessToken: access token не найден ни в заголовке, ни в cookies")
			return "", errors.New("access token не предоставлен")
		}
		tokenStr = cookie.Value
	}

	claims, err := parseJWT(tokenStr)
	if err != nil {
		logger.Info("HTTP", "validateAccessToken: ошибка парсинга JWT: %v", err)
		return "", err
	}
	return claims.Email, nil
}

func generateJWT(email string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := &CustomClaims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		logger.Error("HTTP", "generateJWT: ошибка генерации JWT для пользователя %s: %v", email, err)
		return "", err
	}
	logger.Info("HTTP", "generateJWT: JWT успешно сгенерирован для пользователя %s", email)
	return signedToken, nil
}

func parseJWT(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			err := fmt.Errorf("неизвестный метод подписи: %v", t.Header["alg"])
			logger.Error("HTTP", "parseJWT: ошибка метода подписи: %v", err)
			return nil, err
		}
		return secretKey, nil
	})
	if err != nil {
		logger.Error("HTTP", "parseJWT: ошибка парсинга JWT: %v", err)
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		err := errors.New("не удалось привести claims или токен невалиден")
		logger.Error("HTTP", "parseJWT: неверные claims или невалидный токен: %v", err)
		return nil, err
	}
	return claims, nil
}

func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Expose-Headers", "Authorization")
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	secretFlag := flag.String("secret-key", "", "JWT secret key (required)")
	flag.Parse()

	if *secretFlag == "" {
		log.Fatal("Не задан секретный ключ. Укажите --secret-key=<key>")
	}
	secretKey = []byte(*secretFlag)
	logger.InitLogger(logger.DefaultConfig())
	validate = validator.New()

	r := mux.NewRouter()
	r.HandleFunc("/auth/signup", handleSignUp).Methods(http.MethodPost)
	r.HandleFunc("/auth/login", handleLogin).Methods(http.MethodPost)
	r.HandleFunc("/auth/refresh", handleRefresh).Methods(http.MethodPost)
	r.HandleFunc("/auth/logout", handleLogout).Methods(http.MethodPost)
	r.HandleFunc("/user/profile", handleProfile).Methods(http.MethodGet)
	r.HandleFunc("/file", handleUpload).Methods(http.MethodPost)
	r.HandleFunc("/file", handleGet).Methods(http.MethodGet)

	logger.Info("HTTP", "Сервер запущен на порту 8080")
	if err := http.ListenAndServe(":8080", CorsMiddleware(r)); err != nil {
		logger.Error("HTTP", "Ошибка запуска сервера: %v", err)
		log.Fatal("Ошибка запуска сервера:", err)
	}
}
