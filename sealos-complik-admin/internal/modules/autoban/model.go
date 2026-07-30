package autoban

import "time"

type Source string

const (
	SourceComplik  Source = "complik"
	SourceProcscan Source = "procscan"
)

type Violation struct {
	Namespace    string
	Source       Source
	DetectorName string
	ProcessName  string
	Summary      string
	Detail       string
	IsIllegal    bool
	IsTest       bool
	DetectedAt   time.Time
}
