package service

import (
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq" // Импорт драйвера PostgreSQL (если еще не импортирован в main)

	"github.com/MAJETIXo/Grpc-Auth-Service/internal/config"
	"github.com/MAJETIXo/Grpc-Auth-Service/internal/pb"
	"github.com/MAJETIXo/Grpc-Auth-Service/internal/repository" // <-- Новый импорт
	"github.com/MAJETIXo/Grpc-Auth-Service/pkg/security"        // <-- Новый импорт
)

// AuthServiceServer структура сервиса аутентификации.
type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
	UserRepo repository.UserRepository // <-- Изменено с DB на UserRepo
	Config   *config.Config
}

// NewAuthServiceServer создает новый экземпляр AuthServiceServer.
func NewAuthServiceServer(userRepo repository.UserRepository, cfg *config.Config) *AuthServiceServer {
	return &AuthServiceServer{
		UserRepo: userRepo, // <-- Изменено
		Config:   cfg,
	}
}

// Register обрабатывает запросы на регистрацию нового пользователя.
func (s *AuthServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	log.Printf("Register request received for username: %s", req.GetUsername())

	if req.GetUsername() == "" || req.GetPassword() == "" {
		// Ошибка согласно правке: не раскрывать детали, если данные неверны
		return nil, fmt.Errorf("invalid username or password")
	}

	exists, err := s.UserRepo.UserExists(ctx, req.GetUsername()) // <-- Используем репозиторий
	if err != nil {
		log.Printf("Error checking existing user: %v", err)
		return nil, fmt.Errorf("failed to register user") // Общая ошибка
	}
	if exists {
		return nil, fmt.Errorf("invalid username or password") // Общая ошибка
	}

	hashedPassword, err := security.HashPassword(req.GetPassword()) // <-- Используем пакет security
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return nil, fmt.Errorf("failed to register user") // Общая ошибка
	}

	// Email можно сделать опциональным или генерировать, как сейчас
	err = s.UserRepo.CreateUser(ctx, req.GetUsername(), req.GetUsername()+"@example.com", hashedPassword) // <-- Используем репозиторий
	if err != nil {
		log.Printf("Error inserting user into DB: %v", err)
		return nil, fmt.Errorf("failed to register user") // Общая ошибка
	}

	log.Printf("User '%s' registered successfully", req.GetUsername())
	return &pb.RegisterResponse{Message: "User registered successfully"}, nil
}

// Login обрабатывает запросы на вход пользователя.
func (s *AuthServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	log.Printf("Login request received for username: %s", req.GetUsername())

	if req.GetUsername() == "" || req.GetPassword() == "" {
		// Ошибка согласно правке: не раскрывать детали, если данные неверны
		return nil, fmt.Errorf("invalid username or password")
	}

	user, err := s.UserRepo.GetUserByUsername(ctx, req.GetUsername()) // <-- Используем репозиторий, получаем структуру
	if err != nil {
		log.Printf("Error fetching user from DB: %v", err)
		return nil, fmt.Errorf("invalid username or password") // Общая ошибка
	}
	if user == nil { // Пользователь не найден
		return nil, fmt.Errorf("invalid username or password") // Общая ошибка
	}

	err = security.CheckPassword(user.PasswordHash, req.GetPassword()) // <-- Используем пакет security
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return nil, fmt.Errorf("invalid username or password") // Общая ошибка
		}
		log.Printf("Error comparing passwords: %v", err)
		return nil, fmt.Errorf("invalid username or password") // Общая ошибка
	}

	// Время жизни токена вынесено в конфиг
	tokenExpiration := time.Duration(s.Config.TokenExpirationHours) * time.Hour
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"exp":      time.Now().Add(tokenExpiration).Unix(), // <-- Используем из конфига
	})

	tokenString, err := token.SignedString([]byte(s.Config.JWTSecret))
	if err != nil {
		log.Printf("Error signing JWT token: %v", err)
		return nil, fmt.Errorf("failed to generate token")
	}

	err = s.UserRepo.UpdateLastLogin(ctx, user.ID) // <-- Используем репозиторий
	if err != nil {
		log.Printf("Error updating last_login_at for user %s: %v", user.Username, err)
		// Это не фатальная ошибка для логина, можем продолжить, но логировать стоит
	}

	log.Printf("User '%s' logged in successfully. Token generated.", req.GetUsername())
	return &pb.LoginResponse{Token: tokenString}, nil
}
