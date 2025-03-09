package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
)

func TestMain(m *testing.M) {
	validate = validator.New()

	secretKey = []byte("test_secret")

	code := m.Run()
	os.Exit(code)
}

func TestHandleSignUp(t *testing.T) {
	users = sync.Map{}

	tests := []struct {
		name        string
		requestBody string
		wantStatus  int
		wantInBody  string
	}{
		{
			name:        "ok - valid email/password",
			requestBody: `{"email":"user@example.com","password":"12345678"}`,
			wantStatus:  http.StatusCreated,
			wantInBody:  `"message":"Пользователь user@example.com успешно зарегистрирован"`,
		},
		{
			name:        "bad request - invalid email",
			requestBody: `{"email":"invalidEmail","password":"12345678"}`,
			wantStatus:  http.StatusBadRequest,
			wantInBody:  `"error":"Ошибка валидации"`,
		},
		{
			name:        "bad request - short password",
			requestBody: `{"email":"short@example.com","password":"123"}`,
			wantStatus:  http.StatusBadRequest,
			wantInBody:  `"error":"Ошибка валидации"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/signup", strings.NewReader(tc.requestBody))
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			handleSignUp(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.wantStatus {
				t.Errorf("[%s] got status = %d; want %d", tc.name, res.StatusCode, tc.wantStatus)
			}
			bodyBytes, _ := io.ReadAll(res.Body)
			bodyStr := string(bodyBytes)
			if !strings.Contains(bodyStr, tc.wantInBody) {
				t.Errorf("[%s] body = %q; want to contain %q", tc.name, bodyStr, tc.wantInBody)
			}
		})
	}
}

func TestHandleLogin(t *testing.T) {
	users = sync.Map{}
	user := User{Email: "test@example.com", Password: "12345678"}
	users.Store(user.Email, user)

	tests := []struct {
		name        string
		requestBody string
		wantStatus  int
		wantInBody  string
	}{
		{
			name:        "ok - valid login",
			requestBody: `{"email":"test@example.com","password":"12345678"}`,
			wantStatus:  http.StatusOK,
			wantInBody:  `"message":"Логин успешен"`,
		},
		{
			name:        "unauthorized - user not found",
			requestBody: `{"email":"nope@example.com","password":"somepass"}`,
			wantStatus:  http.StatusUnauthorized,
			wantInBody:  `"error":"Пользователь не найден"`,
		},
		{
			name:        "unauthorized - wrong password",
			requestBody: `{"email":"test@example.com","password":"wrongpass"}`,
			wantStatus:  http.StatusUnauthorized,
			wantInBody:  `"error":"Неверный пароль"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(tc.requestBody))
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			handleLogin(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.wantStatus {
				t.Errorf("[%s] got status = %d; want %d", tc.name, res.StatusCode, tc.wantStatus)
			}
			bodyBytes, _ := io.ReadAll(res.Body)
			bodyStr := string(bodyBytes)
			if !strings.Contains(bodyStr, tc.wantInBody) {
				t.Errorf("[%s] body = %q; want %q", tc.name, bodyStr, tc.wantInBody)
			}
		})
	}
}

func TestHandleRefresh(t *testing.T) {
	sessions = sync.Map{}

	realToken, _ := generateJWT("refresh@example.com", time.Hour)
	sessions.Store(realToken, Session{
		Email:        "refresh@example.com",
		RefreshToken: realToken,
		ExpiresAt:    time.Now().Add(time.Hour),
	})

	expiredJwt, _ := generateJWT("refresh@example.com", -time.Minute)
	sessions.Store(expiredJwt, Session{
		Email:        "refresh@example.com",
		RefreshToken: expiredJwt,
		ExpiresAt:    time.Now().Add(-time.Hour),
	})

	tests := []struct {
		name        string
		cookieValue string
		wantStatus  int
		wantInBody  string
	}{
		{
			name:       "no cookie",
			wantStatus: http.StatusUnauthorized,
			wantInBody: `"refresh-токен не найден"`,
		},
		{
			name:        "expired token",
			cookieValue: expiredJwt,
			wantStatus:  http.StatusUnauthorized,
			wantInBody:  `"refresh-токен просрочен"`,
		},
		{
			name:        "unknown token",
			cookieValue: "some_unknown_string",
			wantStatus:  http.StatusUnauthorized,
			wantInBody:  `"refresh-токен не найден или отозван"`,
		},
		{
			name:        "valid token",
			cookieValue: realToken,
			wantStatus:  http.StatusOK,
			wantInBody:  `"message":"Токены обновлены"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
			if tc.cookieValue != "" {
				req.AddCookie(&http.Cookie{
					Name:  "refresh_token",
					Value: tc.cookieValue,
					Path:  "/",
				})
			}

			rec := httptest.NewRecorder()
			handleRefresh(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.wantStatus {
				t.Errorf("[%s] got status = %d; want %d", tc.name, res.StatusCode, tc.wantStatus)
			}
			bodyBytes, _ := io.ReadAll(res.Body)
			bodyStr := string(bodyBytes)
			if !strings.Contains(bodyStr, tc.wantInBody) {
				t.Errorf("[%s] body = %q; want %q", tc.name, bodyStr, tc.wantInBody)
			}
		})
	}
}

func TestHandleLogout(t *testing.T) {
	sessions = sync.Map{}

	validToken, _ := generateJWT("logout@example.com", time.Hour)
	sessions.Store(validToken, Session{
		Email:        "logout@example.com",
		RefreshToken: validToken,
		ExpiresAt:    time.Now().Add(time.Hour),
	})

	tests := []struct {
		name        string
		cookieValue string
		wantStatus  int
		wantInBody  string
	}{
		{
			name:       "no cookie",
			wantStatus: http.StatusUnauthorized,
			wantInBody: `"refresh-токен не найден"`,
		},
		{
			name:        "already revoked",
			cookieValue: "some_other_token",
			wantStatus:  http.StatusUnauthorized,
			wantInBody:  `"refresh-токен не найден или уже отозван"`,
		},
		{
			name:        "valid token",
			cookieValue: validToken,
			wantStatus:  http.StatusOK,
			wantInBody:  `"message":"Вы успешно вышли из системы"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
			if tc.cookieValue != "" {
				req.AddCookie(&http.Cookie{
					Name:  "refresh_token",
					Value: tc.cookieValue,
					Path:  "/",
				})
			}

			rec := httptest.NewRecorder()
			handleLogout(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.wantStatus {
				t.Errorf("[%s] got status = %d; want %d", tc.name, res.StatusCode, tc.wantStatus)
			}
			bodyBytes, _ := io.ReadAll(res.Body)
			bodyStr := string(bodyBytes)
			if !strings.Contains(bodyStr, tc.wantInBody) {
				t.Errorf("[%s] body = %q; want %q", tc.name, bodyStr, tc.wantInBody)
			}
		})
	}
}

func TestHandleProfile(t *testing.T) {
	users = sync.Map{}
	sessions = sync.Map{}

	user := User{Email: "profile@example.com", Password: "12345678"}
	users.Store(user.Email, user)

	t.Run("unauthorized - no token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
		rec := httptest.NewRecorder()

		handleProfile(rec, req)
		res := rec.Result()
		defer res.Body.Close()

		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("got status = %d; want %d", res.StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("ok - with valid token", func(t *testing.T) {
		access, err := generateJWT("profile@example.com", time.Minute*5)
		if err != nil {
			t.Fatalf("не удалось сгенерировать токен: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
		req.AddCookie(&http.Cookie{
			Name:  "access_token",
			Value: access,
			Path:  "/",
		})

		rec := httptest.NewRecorder()
		handleProfile(rec, req)
		res := rec.Result()
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("got status = %d; want %d", res.StatusCode, http.StatusOK)
		}
		bodyBytes, _ := io.ReadAll(res.Body)
		if !strings.Contains(string(bodyBytes), `"email":"profile@example.com"`) {
			t.Errorf("profile not found in body = %q", string(bodyBytes))
		}
	})
}

func TestHandleUpload(t *testing.T) {
	files = []FileItem{
		{
			ID:         "codes1",
			Title:      "Back Code 1",
			Content:    "0 mb",
			Data:       []string{"BackString"},
			CreateTime: time.Now().Format(time.RFC3339),
			UpdateTime: time.Now().Format(time.RFC3339),
		},
	}

	tests := []struct {
		name        string
		requestBody string
		wantStatus  int
		wantInBody  string
	}{
		{
			name:        "ok - codes1 exists",
			requestBody: `{"projName":"codes1","data":"Some new line"}`,
			wantStatus:  http.StatusOK,
			wantInBody:  `"message":"success"`,
		},
		{
			name:        "not found",
			requestBody: `{"projName":"nonexistent","data":"blabla"}`,
			wantStatus:  http.StatusNotFound,
			wantInBody:  `"error":"FileItem с ID=nonexistent не найден"`,
		},
		{
			name:        "bad JSON",
			requestBody: `{"projName": 123,`,
			wantStatus:  http.StatusBadRequest,

			wantInBody: `"error":"Bad request: unexpected EOF"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/file", strings.NewReader(tc.requestBody))
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			handleUpload(rec, req)

			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.wantStatus {
				t.Errorf("[%s] got status = %d; want %d", tc.name, res.StatusCode, tc.wantStatus)
			}
			bodyBytes, _ := io.ReadAll(res.Body)
			bodyStr := string(bodyBytes)
			if !strings.Contains(bodyStr, tc.wantInBody) {
				t.Errorf("[%s] body = %q; want %q", tc.name, bodyStr, tc.wantInBody)
			}
		})
	}
}

func TestHandleGet(t *testing.T) {
	files = []FileItem{
		{
			ID:         "codes1",
			Title:      "Back Code 1",
			Content:    "0 mb",
			Data:       []string{"BackString"},
			CreateTime: time.Now().Format(time.RFC3339),
			UpdateTime: time.Now().Format(time.RFC3339),
		},
		{
			ID:         "codes2",
			Title:      "Back Code 2",
			Content:    "0 mb",
			Data:       []string{"BackString1", "BackString2"},
			CreateTime: time.Now().Format(time.RFC3339),
			UpdateTime: time.Now().Format(time.RFC3339),
		},
	}

	t.Run("ok - get files", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/file", nil)
		rec := httptest.NewRecorder()
		handleGet(rec, req)

		res := rec.Result()
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Errorf("got status = %d; want %d", res.StatusCode, http.StatusOK)
		}

		var got []FileItem
		if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
			t.Errorf("не смогли распарсить JSON: %v", err)
			return
		}
		if len(got) != 2 {
			t.Errorf("got len=%d; want 2", len(got))
		}
	})
}
