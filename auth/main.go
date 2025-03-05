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
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

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

var users = map[string]User{}

var sessions = map[string]Session{}

var secretKey []byte

const (
	accessTokenTTL  = time.Minute * 5
	refreshTokenTTL = time.Hour * 24
)

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Неверный формат JSON", http.StatusBadRequest)
		return
	}

	if _, exists := users[req.Email]; exists {
		http.Error(w, "Пользователь с таким email уже существует", http.StatusBadRequest)
		return
	}

	user := User{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	}
	users[req.Email] = user

	w.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprintf(w, "Пользователь %s успешно зарегистрирован\n", user.Email)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Неверный формат JSON", http.StatusBadRequest)
		return
	}

	user, ok := users[req.Email]
	if !ok {
		http.Error(w, "Пользователь не найден", http.StatusUnauthorized)
		return
	}

	if user.Password != req.Password {
		http.Error(w, "Неверный пароль", http.StatusUnauthorized)
		return
	}

	accessToken, err := generateJWT(user.Email, accessTokenTTL)
	if err != nil {
		http.Error(w, "Не удалось сгенерировать access-токен", http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateJWT(user.Email, refreshTokenTTL)
	if err != nil {
		http.Error(w, "Не удалось сгенерировать refresh-токен", http.StatusInternalServerError)
		return
	}

	sessions[refreshToken] = Session{
		Email:        user.Email,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(refreshTokenTTL),
	}

	resp := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Ошибка при формировании JSON-ответа", http.StatusInternalServerError)
		return
	}
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Неверный формат JSON", http.StatusBadRequest)
		return
	}

	session, ok := sessions[req.RefreshToken]
	if !ok {
		http.Error(w, "refresh-токен не найден или отозван", http.StatusUnauthorized)
		return
	}

	if time.Now().After(session.ExpiresAt) {
		delete(sessions, req.RefreshToken)
		http.Error(w, "refresh-токен просрочен", http.StatusUnauthorized)
		return
	}

	claims, err := parseJWT(req.RefreshToken)
	if err != nil {
		delete(sessions, req.RefreshToken)
		http.Error(w, "refresh-токен невалиден", http.StatusUnauthorized)
		return
	}

	newAccess, err := generateJWT(claims.Email, accessTokenTTL)
	if err != nil {
		http.Error(w, "Ошибка генерации нового access-токена", http.StatusInternalServerError)
		return
	}
	newRefresh, err := generateJWT(claims.Email, refreshTokenTTL)
	if err != nil {
		http.Error(w, "Ошибка генерации нового refresh-токена", http.StatusInternalServerError)
		return
	}

	delete(sessions, req.RefreshToken)

	sessions[newRefresh] = Session{
		Email:        claims.Email,
		RefreshToken: newRefresh,
		ExpiresAt:    time.Now().Add(refreshTokenTTL),
	}

	resp := map[string]string{
		"access_token":  newAccess,
		"refresh_token": newRefresh,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Ошибка при формировании JSON-ответа", http.StatusInternalServerError)
		return
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Неверный формат JSON", http.StatusBadRequest)
		return
	}

	if _, ok := sessions[req.RefreshToken]; !ok {
		http.Error(w, "refresh-токен не найден или уже отозван", http.StatusUnauthorized)
		return
	}
	delete(sessions, req.RefreshToken)
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "Вы успешно вышли из системы")
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	email, err := validateAccessToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	user, ok := users[email]
	if !ok {
		http.Error(w, "Неверный логин или пароль", http.StatusNotFound)
		return
	}

	resp := map[string]string{
		"name":  user.Name,
		"email": user.Email,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Ошибка при формировании JSON-ответа", http.StatusInternalServerError)
		return
	}
}

func handleFTPPost(w http.ResponseWriter, r *http.Request) {
	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Неверный формат JSON", http.StatusBadRequest)
		return
	}
	userVal, ok := payload["user"].(string)
	if !ok || userVal == "" {
		http.Error(w, "Отсутствует или неверное поле user", http.StatusBadRequest)
		return
	}
	fileName, ok := payload["fileName"].(string)
	if !ok || fileName == "" {
		http.Error(w, "Отсутствует или неверное поле fileName", http.StatusBadRequest)
		return
	}

	dirPath := fmt.Sprintf("./%s", userVal)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		http.Error(w, "Не удалось создать директорию", http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Ошибка при обработке JSON", http.StatusInternalServerError)
		return
	}

	filePath := fmt.Sprintf("%s/%s", dirPath, fileName)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		http.Error(w, "Ошибка при сохранении файла", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprintf(w, "Файл сохранен по пути: %s", filePath)
}

func handleFTPGet(w http.ResponseWriter, r *http.Request) {
	userVal := r.URL.Query().Get("user")
	fileName := r.URL.Query().Get("filename")
	if userVal == "" || fileName == "" {
		http.Error(w, "Отсутствуют параметры user или filename", http.StatusBadRequest)
		return
	}

	filePath := fmt.Sprintf("./%s/%s", userVal, fileName)
	data, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Файл не найден", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(data); err != nil {
		http.Error(w, "Ошибка при отправке данных", http.StatusInternalServerError)
		return
	}
}

func validateAccessToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("заголовок Authorization отсутствует")
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("некорректный заголовок Authorization")
	}
	tokenStr := parts[1]
	claims, err := parseJWT(tokenStr)
	if err != nil {
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
	return token.SignedString(secretKey)
}

func parseJWT(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("неизвестный метод подписи: %v", t.Header["alg"])
		}
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, errors.New("не удалось привести claims или токен невалиден")
	}
	return claims, nil
}

func main() {
	secretFlag := flag.String("secret-key", "", "JWT secret key (required)")
	flag.Parse()

	if *secretFlag == "" {
		log.Fatal("Не задан секретный ключ. Укажите --secret-key=<key>")
	}
	secretKey = []byte(*secretFlag)

	router := mux.NewRouter()
	router.HandleFunc("/auth/signup", handleSignUp).Methods(http.MethodPost)
	router.HandleFunc("/auth/login", handleLogin).Methods(http.MethodPost)
	router.HandleFunc("/auth/refresh", handleRefresh).Methods(http.MethodPost)
	router.HandleFunc("/auth/logout", handleLogout).Methods(http.MethodPost)
	router.HandleFunc("/user/profile", handleProfile).Methods(http.MethodGet)

	router.HandleFunc("/ftp", handleFTPPost).Methods(http.MethodPost)
	router.HandleFunc("/ftp", handleFTPGet).Methods(http.MethodGet)

	log.Println("Сервер запущен на порту 8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal("Ошибка запуска сервера:", err)
	}
}
