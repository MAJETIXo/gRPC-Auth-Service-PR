package config

import (
	"log"
	"os"
	"strconv"
)

type Config struct {
	DatabaseURL          string
	GRPCServerAddress    string
	JWTSecret            string
	TokenExpirationHours int
}

func LoadConfig() *Config {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	grpcAddr := os.Getenv("GRPC_SERVER_ADDRESS")
	if grpcAddr == "" {
		grpcAddr = ":50051"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}

	tokenExpStr := os.Getenv("JWT_TOKEN_EXPIRATION_HOURS")
	tokenExp, err := strconv.Atoi(tokenExpStr)
	if err != nil || tokenExp <= 0 {
		log.Printf("JWT_TOKEN_EXPIRATION_HOURS is not set or invalid, defaulting to 24 hours. Error: %v", err)
		tokenExp = 24
	}

	return &Config{
		DatabaseURL:          dbURL,
		GRPCServerAddress:    grpcAddr,
		JWTSecret:            jwtSecret,
		TokenExpirationHours: tokenExp,
	}
}
