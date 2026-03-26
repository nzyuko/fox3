package db

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"path/filepath"
)

var DB *gorm.DB

// InitDB initializes the SQLite database
func InitDB() {
	current, err := os.Getwd()
	if err != nil {
		log.Fatalf("failed to get current working directory: %v", err)
	}

	dbPath := filepath.Join(current, "data", "fox3.db")
	
	// Ensure data directory exists
	err = os.MkdirAll(filepath.Dir(dbPath), 0750)
	if err != nil {
		log.Fatalf("failed to create data directory: %v", err)
	}

	// Enable WAL mode and busy timeout to prevent blocking under concurrent access
	dsn := dbPath + "?_journal_mode=wal&_busy_timeout=5000"
	DB, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// Allow multiple readers with WAL mode
	sqlDB, err := DB.DB()
	if err == nil {
		sqlDB.SetMaxOpenConns(4)
	}

	log.Printf("Database initialized at %s", dbPath)
}
