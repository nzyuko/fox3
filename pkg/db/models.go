package db

import (
	"gorm.io/gorm"
	"time"
)

type AgentModel struct {
	ID            string `gorm:"primaryKey"`
	Alive         bool
	Authenticated bool
	Initial       time.Time
	Checkin       time.Time
	Secret        []byte
	Note          string
	
	// Relationships
	Host      HostModel    `gorm:"foreignKey:AgentID"`
	Process   ProcessModel `gorm:"foreignKey:AgentID"`
	Comms     CommsModel   `gorm:"foreignKey:AgentID"`
}

type HostModel struct {
	gorm.Model
	AgentID      string `gorm:"uniqueIndex"`
	Name         string
	Platform     string
	Architecture string
	IPs          string // Stored as comma-separated or JSON
}

type ProcessModel struct {
	gorm.Model
	AgentID   string `gorm:"uniqueIndex"`
	PID       int    `gorm:"column:pid"`
	Name      string
	UserName  string `gorm:"column:user_name"`
	Domain    string
	Integrity int
}

type CommsModel struct {
	gorm.Model
	AgentID  string `gorm:"uniqueIndex"`
	Protocol string
	Sleep    int
	Jitter   int
	Padding  int
}

type CredentialModel struct {
	ID       string `gorm:"primaryKey"`
	Domain   string
	Username string
	Password string
	Hash     string
	Source   string
	AgentID  string
	Created  time.Time
}

type ScreenshotModel struct {
	ID      string `gorm:"primaryKey"`
	AgentID string
	Data    []byte
	Note    string
	Created time.Time
}

type PivotModel struct {
	ID            string `gorm:"primaryKey"`
	Name          string
	ParentAgentID string `gorm:"index"`
	ChildAgentID  string `gorm:"index"`
	Protocol      string // "smb" or "tcp"
	Created       time.Time
}

func AutoMigrate() {
	if DB == nil {
		return
	}
	DB.AutoMigrate(&AgentModel{}, &HostModel{}, &ProcessModel{}, &CommsModel{}, &CredentialModel{}, &ScreenshotModel{}, &PivotModel{})
}
