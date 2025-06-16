package main

import (
	"context"
	"database/sql"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/MAJETIXo/Grpc-Auth-Service/internal/config"
	"github.com/MAJETIXo/Grpc-Auth-Service/internal/pb"
	"github.com/MAJETIXo/Grpc-Auth-Service/internal/service"
)

const (
	grpcPort = ":50051"
)

func main() {
	log.Println("Starting gRPC Auth Service...")

	cfg := config.LoadConfig()
	log.Println("Configuration loaded successfully.")

	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing database connection: %v", err)
		} else {
			log.Println("Database connection closed.")
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		log.Fatalf("failed to ping database: %v", err)
	}
	log.Println("Successfully connected to PostgreSQL database.")

	s := grpc.NewServer()

	// 4. Регистрация нашего сервиса авторизации
	authService := service.NewAuthServiceServer(db, cfg)
	pb.RegisterAuthServiceServer(s, authService)
	log.Println("AuthService registered.")

	reflection.Register(s)

	lis, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("failed to listen on port %s: %v", grpcPort, err)
	}

	log.Printf("gRPC server listening on port %s", grpcPort)

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Shutting down gRPC server gracefully...")
		s.GracefulStop() // Мягко останавливаем сервер
		log.Println("gRPC server stopped.")
	}()

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve gRPC: %v", err)
	}
}

//Эта штука нужна здесь для PR потому что я залил все в main
