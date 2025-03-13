package database

import (
	"database/sql"
	"embed"
	"errors"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

var (
	ErrNoChange  = migrate.ErrNoChange
	ErrEmptyPath = errors.New("empty path")
)

const PATH = "migrations"

//go:embed migrations/*.sql
var fs embed.FS

func Migrate(db *sql.DB, databaseName string) error {
	d, err := iofs.New(fs, PATH)
	if err != nil {
		return err
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithInstance("iofs", d, databaseName, driver)
	if err != nil {
		return err
	}

	if err := m.Up(); errors.Is(err, migrate.ErrNoChange) {
		return nil
	} else if err != nil {
		return err
	}

	return nil
}

func New(source, filePath, database string) (*migrate.Migrate, error) {
	if filePath == "" {
		return nil, ErrEmptyPath
	}
	filePath = strings.ReplaceAll(filePath, "\\", "/")

	m, err := migrate.New(source+"://"+filePath, database)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func NewWithSourceInstance(sourceName string, sourceInstance source.Driver, databaseURL string) (*migrate.Migrate, error) {
	m, err := migrate.NewWithSourceInstance(sourceName, sourceInstance, databaseURL)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func NewWithInstance(sourceName string, sourceInstance source.Driver, databaseName string, databaseInstance database.Driver) (*migrate.Migrate, error) {
	m, err := migrate.NewWithInstance(sourceName, sourceInstance, databaseName, databaseInstance)
	if err != nil {
		return nil, err
	}

	return m, nil
}
