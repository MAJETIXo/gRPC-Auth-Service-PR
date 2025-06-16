package service

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq" // Импорт драйвера PostgreSQL
	"golang.org/x/crypto/bcrypt"

	"github.com/MAJETIXo/Grpc-Auth-Service/internal/config"
	"github.com/MAJETIXo/Grpc-Auth-Service/internal/pb"
)

type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
	DB     *sql.DB
	Config *config.Config
}

func NewAuthServiceServer(db *sql.DB, cfg *config.Config) *AuthServiceServer {
	return &AuthServiceServer{
		DB:     db,
		Config: cfg,
	}
}

func (s *AuthServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	log.Printf("Register request received for username: %s", req.GetUsername())

	if req.GetUsername() == "" || req.GetPassword() == "" {
		return nil, fmt.Errorf("username and password cannot be empty")
	}

	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`
	err := s.DB.QueryRowContext(ctx, query, req.GetUsername()).Scan(&exists)
	if err != nil {
		log.Printf("Error checking existing user: %v", err)
		return nil, fmt.Errorf("failed to check user existence")
	}
	if exists {
		return nil, fmt.Errorf("user with username '%s' already exists", req.GetUsername())
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.GetPassword()), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return nil, fmt.Errorf("failed to hash password")
	}

	insertQuery := `
		INSERT INTO users (username, email, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`
	_, err = s.DB.ExecContext(ctx, insertQuery, req.GetUsername(), req.GetUsername()+"@example.com", string(hashedPassword))
	if err != nil {
		log.Printf("Error inserting user into DB: %v", err)
		return nil, fmt.Errorf("failed to register user")
	}

	log.Printf("User '%s' registered successfully", req.GetUsername())
	return &pb.RegisterResponse{Message: "User registered successfully"}, nil
}

func (s *AuthServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	log.Printf("Login request received for username: %s", req.GetUsername())

	if req.GetUsername() == "" || req.GetPassword() == "" {
		return nil, fmt.Errorf("username and password cannot be empty")
	}

	var userID string
	var hashedPassword string
	var username string
	query := `SELECT id, username, password_hash FROM users WHERE username = $1`
	err := s.DB.QueryRowContext(ctx, query, req.GetUsername()).Scan(&userID, &username, &hashedPassword)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid credentials: user not found")
	}
	if err != nil {
		log.Printf("Error fetching user from DB: %v", err)
		return nil, fmt.Errorf("failed to login: database error")
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.GetPassword()))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return nil, fmt.Errorf("invalid credentials: wrong password")
		}
		log.Printf("Error comparing passwords: %v", err)
		return nil, fmt.Errorf("failed to login: password comparison error")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Токен истекает через 24 часа
	})

	tokenString, err := token.SignedString([]byte(s.Config.JWTSecret))
	if err != nil {
		log.Printf("Error signing JWT token: %v", err)
		return nil, fmt.Errorf("failed to generate token")
	}

	updateLoginQuery := `UPDATE users SET last_login_at = NOW() WHERE id = $1`
	_, err = s.DB.ExecContext(ctx, updateLoginQuery, userID)
	if err != nil {
		log.Printf("Error updating last_login_at for user %s: %v", username, err)
		// Это не фатальная ошибка, можем продолжить, но логировать стоит
	}

	log.Printf("User '%s' logged in successfully. Token generated.", req.GetUsername())
	return &pb.LoginResponse{Token: tokenString}, nil
}
