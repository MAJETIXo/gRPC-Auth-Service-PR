package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL string
	JWTSecret   string
}

func LoadConfig() *Config {
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found, loading config from environment variables. Error: %v", err)
	}

	cfg := &Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
	}

	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}
	if cfg.JWTSecret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}

	return cfg
}
