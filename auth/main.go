package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-park-mail-ru/2025_1_Quza/platform/pkg/logger"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

var validate *validator.Validate

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

type UploadRequest struct {
	Email    string `json:"email" validate:"required,email"`
	File     string `json:"file" validate:"required"`
	FileName string `json:"file_name" validate:"required"`
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
		http.Error(w, "Неверный формат JSON", http.StatusBadRequest)
		return
	}

	if err := validate.Struct(req); err != nil {
		logger.Error("HTTP", "handleSignUp: ошибка валидации: %v", err)
		http.Error(w, "Ошибка валидации", http.StatusBadRequest)
		return
	}

	if _, exists := users.Load(req.Email); exists {
		logger.Info("HTTP", "handleSignUp: попытка регистрации уже существующего пользователя %s", req.Email)
		http.Error(w, "Пользователь с таким email уже существует", http.StatusBadRequest)
		return
	}

	user := User{
		Email:    req.Email,
		Password: req.Password,
	}
	users.Store(user.Email, user)

	logger.Info("HTTP", "handleSignUp: пользователь %s успешно зарегистрирован", user.Email)
	w.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprintf(w, "Пользователь %s успешно зарегистрирован\n", user.Email)
}
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Error("HTTP", "handleLogin: ошибка декодирования JSON: %v", err)
		http.Error(w, "Неверный формат JSON", http.StatusBadRequest)
		return
	}

	if err := validate.Struct(req); err != nil {
		logger.Error("HTTP", "handleLogin: ошибка валидации: %v", err)
		http.Error(w, "Ошибка валидации", http.StatusBadRequest)
		return
	}

	user, ok := users.Load(req.Email)
	if !ok {
		logger.Info("HTTP", "handleLogin: пользователь %s не найден", req.Email)
		http.Error(w, "Пользователь не найден", http.StatusUnauthorized)
		return
	}

	us, ok := user.(User)
	if !ok {
		logger.Error("HTTP", "handleLogin: ошибка приведения типа пользователя")
		http.Error(w, "Ошибка при конвертации пользователя", http.StatusInternalServerError)
		return
	}

	if us.Password != req.Password {
		logger.Info("HTTP", "handleLogin: неверный пароль для пользователя %s", req.Email)
		http.Error(w, "Неверный пароль", http.StatusUnauthorized)
		return
	}

	accessToken, err := generateJWT(us.Email, accessTokenTTL)
	if err != nil {
		logger.Error("HTTP", "handleLogin: не удалось сгенерировать access-токен: %v", err)
		http.Error(w, "Не удалось сгенерировать access-токен", http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateJWT(us.Email, refreshTokenTTL)
	if err != nil {
		logger.Error("HTTP", "handleLogin: не удалось сгенерировать refresh-токен: %v", err)
		http.Error(w, "Не удалось сгенерировать refresh-токен", http.StatusInternalServerError)
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Логин успешен",
	})
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshCookie, err := r.Cookie("refresh_token")
	if err != nil {
		logger.Error("HTTP", "handleRefresh: refresh-токен не найден в cookies: %v", err)
		http.Error(w, "refresh-токен не найден", http.StatusUnauthorized)
		return
	}

	var req RefreshRequest
	req.RefreshToken = refreshCookie.Value

	if err := validate.Struct(req); err != nil {
		logger.Error("HTTP", "handleRefresh: ошибка валидации: %v", err)
		http.Error(w, "Ошибка валидации", http.StatusBadRequest)
		return
	}

	session, ok := sessions.Load(req.RefreshToken)
	if !ok {
		logger.Info("HTTP", "handleRefresh: refresh-токен %s не найден или отозван", req.RefreshToken)
		http.Error(w, "refresh-токен не найден или отозван", http.StatusUnauthorized)
		return
	}

	formatSession, ok := session.(Session)
	if !ok {
		logger.Error("HTTP", "handleRefresh: ошибка приведения типа сессии")
		http.Error(w, "Ошибка при конвертации сессии", http.StatusInternalServerError)
		return
	}

	if time.Now().After(formatSession.ExpiresAt) {
		sessions.Delete(req.RefreshToken)
		logger.Info("HTTP", "handleRefresh: refresh-токен %s просрочен", req.RefreshToken)
		http.Error(w, "refresh-токен просрочен", http.StatusUnauthorized)
		return
	}

	claims, err := parseJWT(req.RefreshToken)
	if err != nil {
		sessions.Delete(req.RefreshToken)
		logger.Error("HTTP", "handleRefresh: невалидный refresh-токен: %v", err)
		http.Error(w, "refresh-токен невалиден", http.StatusUnauthorized)
		return
	}

	newAccess, err := generateJWT(claims.Email, accessTokenTTL)
	if err != nil {
		logger.Error("HTTP", "handleRefresh: ошибка генерации нового access-токена: %v", err)
		http.Error(w, "Ошибка генерации нового access-токена", http.StatusInternalServerError)
		return
	}
	newRefresh, err := generateJWT(claims.Email, refreshTokenTTL)
	if err != nil {
		logger.Error("HTTP", "handleRefresh: ошибка генерации нового refresh-токена: %v", err)
		http.Error(w, "Ошибка генерации нового refresh-токена", http.StatusInternalServerError)
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
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Токены обновлены",
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	refreshCookie, err := r.Cookie("refresh_token")
	if err != nil {
		logger.Info("HTTP", "handleLogout: refresh-токен не найден в cookies")
	} else {
		var req RefreshRequest
		req.RefreshToken = refreshCookie.Value

		if err := validate.Struct(req); err != nil {
			logger.Error("HTTP", "handleLogout: ошибка валидации: %v", err)
			http.Error(w, "Ошибка валидации", http.StatusBadRequest)
			return
		}

		if _, ok := sessions.Load(req.RefreshToken); !ok {
			logger.Info("HTTP", "handleLogout: refresh-токен %s не найден или уже отозван", req.RefreshToken)
			http.Error(w, "refresh-токен не найден или уже отозван", http.StatusUnauthorized)
			return
		}
		sessions.Delete(req.RefreshToken)
	}

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
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "Вы успешно вышли из системы")
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	email, err := validateAccessToken(r)
	if err != nil {
		logger.Info("HTTP", "handleProfile: ошибка валидации access-токена: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	user, ok := users.Load(email)
	if !ok {
		logger.Info("HTTP", "handleProfile: пользователь %s не найден", email)
		http.Error(w, "Неверный логин или пароль", http.StatusNotFound)
		return
	}

	usFormat, ok := user.(User)
	if !ok {
		logger.Error("HTTP", "handleProfile: ошибка приведения типа пользователя")
		http.Error(w, "Ошибка при конвертации пользователя", http.StatusInternalServerError)
		return
	}

	logger.Info("HTTP", "handleProfile: профиль пользователя %s запрошен", email)
	resp := map[string]string{
		"name":  usFormat.Name,
		"email": usFormat.Email,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Error("HTTP", "handleProfile: ошибка формирования JSON-ответа: %v", err)
		http.Error(w, "Ошибка при формировании JSON-ответа", http.StatusInternalServerError)
		return
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	var payload UploadRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		logger.Error("HTTP", "handleUpload: ошибка декодирования JSON: %v", err)
		http.Error(w, "Неверный формат JSON", http.StatusBadRequest)
		return
	}

	if err := validate.Struct(payload); err != nil {
		logger.Error("HTTP", "handleUpload: ошибка валидации: %v", err)
		http.Error(w, "Ошибка валидации", http.StatusBadRequest)
		return
	}

	dirPath := fmt.Sprintf("./%s", payload.Email)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		logger.Error("HTTP", "handleUpload: не удалось создать директорию: %v", err)
		http.Error(w, "Не удалось создать директорию", http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(payload)
	if err != nil {
		logger.Error("HTTP", "handleUpload: ошибка маршаллинга JSON: %v", err)
		http.Error(w, "Ошибка при обработке JSON", http.StatusInternalServerError)
		return
	}

	filePath := fmt.Sprintf("%s/%s", dirPath, payload.FileName)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		logger.Error("HTTP", "handleUpload: ошибка записи файла: %v", err)
		http.Error(w, "Ошибка при сохранении файла", http.StatusInternalServerError)
		return
	}

	logger.Info("HTTP", "handleUpload: файл %s сохранен для пользователя %s", payload.FileName, payload.Email)
	w.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprintf(w, "Файл сохранен по пути: %s", filePath)
}

func handleGet(w http.ResponseWriter, r *http.Request) {
	userVal := r.URL.Query().Get("user")
	fileName := r.URL.Query().Get("filename")
	if userVal == "" || fileName == "" {
		logger.Info("HTTP", "handleGet: отсутствуют параметры user или filename")
		http.Error(w, "Отсутствуют параметры user или filename", http.StatusBadRequest)
		return
	}

	filePath := fmt.Sprintf("./%s/%s", userVal, fileName)
	data, err := os.ReadFile(filePath)
	if err != nil {
		logger.Info("HTTP", "handleGet: файл %s для пользователя %s не найден", fileName, userVal)
		http.Error(w, "Файл не найден", http.StatusNotFound)
		return
	}

	logger.Info("HTTP", "handleGet: файл %s успешно получен для пользователя %s", fileName, userVal)
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(data); err != nil {
		logger.Error("HTTP", "handleGet: ошибка отправки данных: %v", err)
		http.Error(w, "Ошибка при отправке данных", http.StatusInternalServerError)
		return
	}
}

func validateAccessToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		logger.Info("HTTP", "validateAccessToken: заголовок Authorization отсутствует")
		return "", errors.New("заголовок Authorization отсутствует")
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		logger.Info("HTTP", "validateAccessToken: некорректный заголовок Authorization")
		return "", errors.New("некорректный заголовок Authorization")
	}
	tokenStr := parts[1]
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
		logger.Error("HTTP]", "parseJWT: ошибка парсинга JWT: %v", err)
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

	router := mux.NewRouter()

	router.Use(CorsMiddleware)

	router.HandleFunc("/auth/signup", handleSignUp).Methods(http.MethodPost)
	router.HandleFunc("/auth/login", handleLogin).Methods(http.MethodPost)
	router.HandleFunc("/auth/refresh", handleRefresh).Methods(http.MethodPost)
	router.HandleFunc("/auth/logout", handleLogout).Methods(http.MethodPost)
	router.HandleFunc("/user/profile", handleProfile).Methods(http.MethodGet)
	router.HandleFunc("/file", handleUpload).Methods(http.MethodPost)
	router.HandleFunc("/file", handleGet).Methods(http.MethodGet)

	logger.Info("HTTP", "Сервер запущен на порту 8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		logger.Error("HTTP", "Ошибка запуска сервера: %v", err)
		log.Fatal("Ошибка запуска сервера:", err)
	}
}
