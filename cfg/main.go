package main

import (
	"database/sql"
	"github.com/joho/godotenv"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/lib/pq"

	"google.golang.org/grpc"

	"github.com/MAJETIXo/Grpc-Auth-Service/internal/config"
	"github.com/MAJETIXo/Grpc-Auth-Service/internal/pb"
	"github.com/MAJETIXo/Grpc-Auth-Service/internal/repository"
	"github.com/MAJETIXo/Grpc-Auth-Service/internal/service"
)

func main() {

	err := godotenv.Load() // По умолчанию ищет .env в текущей директории
	if err != nil {
		log.Println("Error loading .env file, assuming environment variables are set externally")
		// Не обязательно фатальная ошибка, если переменные уже установлены в окружении
	}
	cfg := config.LoadConfig()

	// Инициализация базы данных
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatalf("failed to ping database: %v", err)
	}
	log.Println("Successfully connected to the database!")

	// Инициализация репозитория пользователей
	userRepo := repository.NewPostgresUserRepository(db)

	// Инициализация gRPC сервера
	lis, err := net.Listen("tcp", cfg.GRPCServerAddress)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	authServiceServer := service.NewAuthServiceServer(userRepo, cfg)
	pb.RegisterAuthServiceServer(s, authServiceServer)

	log.Printf("gRPC server listening on %s", cfg.GRPCServerAddress)

	// Запуск gRPC сервера в горутине
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down gRPC server...")
	s.GracefulStop()
	log.Println("gRPC server gracefully stopped.")
}
