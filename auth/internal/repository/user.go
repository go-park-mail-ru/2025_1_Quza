package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-park-mail-ru/2025_1_Quza/auth/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Storage struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) UserRepositoryInterface {
	return &Storage{pool: pool}
}

func (s *Storage) Save(ctx context.Context, user model.User) (int, error) {
	query := `
		INSERT INTO users (name, email, role, password)
		VALUES ($1, $2, $3, $4)
		RETURNING id`
	var id int
	err := s.pool.QueryRow(ctx, query, user.Name, user.Email, user.Role, user.Password).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("error inserting user into database: %w", err)
	}

	return id, nil
}

func (s *Storage) Update(ctx context.Context, user model.User) error {
	query := `
		UPDATE users
		SET name = $1, email = $2, role = $3, password = $4
		WHERE id = $5`
	cmdTag, err := s.pool.Exec(ctx, query, user.Name, user.Email, user.Role, user.Password, user.ID)
	if err != nil {
		return err
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("no user found with id %d", user.ID)
	}

	return nil
}

func (s *Storage) Delete(ctx context.Context, id int) error {
	query := "DELETE FROM users WHERE id = $1"
	cmdTag, err := s.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("error deleting user from database: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return fmt.Errorf("no user found with id %d", id)
	}

	return nil
}

func (s *Storage) GetUserById(ctx context.Context, id int) (*model.User, error) {
	query := `
		SELECT id, name, email, role, password, created_at, updated_at
		FROM users
		WHERE id = $1`
	var user model.User
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Role,
		&user.Password,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user with id %d does not exist: %w", id, err)
		}
		return nil, fmt.Errorf("error querying user by id: %w", err)
	}

	return &user, nil
}

func (s *Storage) GetUserByName(ctx context.Context, name string) (*model.User, error) {
	query := `
		SELECT id, name, email, role, password, created_at, updated_at
		FROM users
		WHERE name = $1`
	var user model.User
	err := s.pool.QueryRow(ctx, query, name).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Role,
		&user.Password,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user with name %s does not exist: %w", name, err)
		}
		return nil, fmt.Errorf("error querying user by name: %w", err)
	}
	return &user, nil
}
