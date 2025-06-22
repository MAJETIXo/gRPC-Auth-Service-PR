package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/MAJETIXo/Grpc-Auth-Service/internal/config"
	"github.com/MAJETIXo/Grpc-Auth-Service/internal/pb"
	"github.com/MAJETIXo/Grpc-Auth-Service/internal/repository"
	"github.com/MAJETIXo/Grpc-Auth-Service/internal/service"
	"github.com/MAJETIXo/Grpc-Auth-Service/mocks"
	"github.com/MAJETIXo/Grpc-Auth-Service/pkg/security"
)

func setupTestConfig() *config.Config {
	return &config.Config{
		JWTSecret:            "test-secret",
		TokenExpirationHours: 1,
	}
}

func TestAuthService_Register(t *testing.T) {

	mockUserRepo := mocks.NewUserRepository(t)
	cfg := setupTestConfig()
	authService := service.NewAuthServiceServer(mockUserRepo, cfg)
	ctx := context.Background()

	t.Run("successful registration", func(t *testing.T) {
		req := &pb.RegisterRequest{
			Username: "newuser",
			Password: "newpassword",
		}

		mockUserRepo.On("UserExists", ctx, req.GetUsername()).Return(false, nil).Once()
		mockUserRepo.On("CreateUser", ctx, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

		resp, err := authService.Register(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "User registered successfully", resp.GetMessage())
	})

	t.Run("registration with empty username", func(t *testing.T) {
		req := &pb.RegisterRequest{
			Username: "",
			Password: "password",
		}

		resp, err := authService.Register(ctx, req)
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.EqualError(t, err, "invalid username or password")
	})

	t.Run("registration with empty password", func(t *testing.T) {
		req := &pb.RegisterRequest{
			Username: "user",
			Password: "",
		}

		resp, err := authService.Register(ctx, req)
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.EqualError(t, err, "invalid username or password")
	})

	t.Run("registration with existing username", func(t *testing.T) {
		req := &pb.RegisterRequest{
			Username: "existinguser",
			Password: "password",
		}

		mockUserRepo.On("UserExists", ctx, req.GetUsername()).Return(true, nil).Once()

		resp, err := authService.Register(ctx, req)
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.EqualError(t, err, "invalid username or password") // Общая ошибка, как в сервисе
	})

	t.Run("database error during UserExists check", func(t *testing.T) {
		req := &pb.RegisterRequest{
			Username: "dbuser",
			Password: "dbpassword",
		}

		mockUserRepo.On("UserExists", ctx, req.GetUsername()).Return(false, errors.New("db error")).Once()

		resp, err := authService.Register(ctx, req)
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.EqualError(t, err, "failed to register user") // Общая ошибка
	})

	t.Run("database error during CreateUser", func(t *testing.T) {
		req := &pb.RegisterRequest{
			Username: "erroruser",
			Password: "errorpassword",
		}

		mockUserRepo.On("UserExists", ctx, req.GetUsername()).Return(false, nil).Once()
		mockUserRepo.On("CreateUser", ctx, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("insert error")).Once()

		resp, err := authService.Register(ctx, req)
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.EqualError(t, err, "failed to register user") // Общая ошибка
	})
}

func TestAuthService_Login(t *testing.T) {

	mockUserRepo := mocks.NewUserRepository(t)
	cfg := setupTestConfig()
	authService := service.NewAuthServiceServer(mockUserRepo, cfg)
	ctx := context.Background()

	testUser := &repository.User{
		ID:           "123",
		Username:     "testuser",
		PasswordHash: "", // Будет установлена в тесте
		Email:        "testuser@example.com",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		LastLoginAt:  nil,
	}

	t.Run("successful login", func(t *testing.T) {
		req := &pb.LoginRequest{
			Username: "testuser",
			Password: "testpassword",
		}

		hashedPassword, _ := security.HashPassword(req.GetPassword())
		testUser.PasswordHash = hashedPassword

		mockUserRepo.On("GetUserByUsername", ctx, req.GetUsername()).Return(testUser, nil).Once()
		mockUserRepo.On("UpdateLastLogin", ctx, testUser.ID).Return(nil).Once()

		resp, err := authService.Login(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.GetToken())
	})

	t.Run("login with empty username", func(t *testing.T) {
		req := &pb.LoginRequest{
			Username: "",
			Password: "password",
		}

		resp, err := authService.Login(ctx, req)
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.EqualError(t, err, "invalid username or password")
	})

	t.Run("login with empty password", func(t *testing.T) {
		req := &pb.LoginRequest{
			Username: "user",
			Password: "",
		}

		resp, err := authService.Login(ctx, req)
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.EqualError(t, err, "invalid username or password")
	})

	t.Run("login with non-existent user", func(t *testing.T) {
		req := &pb.LoginRequest{
			Username: "nonexistent",
			Password: "password",
		}
		mockUserRepo.On("GetUserByUsername", ctx, req.GetUsername()).Return(nil, nil).Once()

		resp, err := authService.Login(ctx, req)
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.EqualError(t, err, "invalid username or password")
	})

	t.Run("login with wrong password", func(t *testing.T) {
		req := &pb.LoginRequest{
			Username: "testuser",
			Password: "wrongpassword", // Неправильный пароль
		}

		hashedPassword, _ := security.HashPassword("correctpassword")
		testUser.PasswordHash = hashedPassword

		mockUserRepo.On("GetUserByUsername", ctx, req.GetUsername()).Return(testUser, nil).Once()

		resp, err := authService.Login(ctx, req)
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.EqualError(t, err, "invalid username or password") // Общая ошибка
	})

	t.Run("database error during GetUserByUsername", func(t *testing.T) {
		req := &pb.LoginRequest{
			Username: "dbuser",
			Password: "dbpassword",
		}
		mockUserRepo.On("GetUserByUsername", ctx, req.GetUsername()).Return(nil, errors.New("db error")).Once()

		resp, err := authService.Login(ctx, req)
		require.Error(t, err)
		assert.Nil(t, resp)
		assert.EqualError(t, err, "invalid username or password") // Общая ошибка
	})

	t.Run("error updating last login (non-fatal)", func(t *testing.T) {
		req := &pb.LoginRequest{
			Username: "testuser",
			Password: "testpassword",
		}
		hashedPassword, _ := security.HashPassword(req.GetPassword())
		testUser.PasswordHash = hashedPassword

		mockUserRepo.On("GetUserByUsername", ctx, req.GetUsername()).Return(testUser, nil).Once()
		mockUserRepo.On("UpdateLastLogin", ctx, testUser.ID).Return(errors.New("update error")).Once()

		resp, err := authService.Login(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.GetToken())
	})
}
