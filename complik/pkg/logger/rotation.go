// Copyright 2025 CompliK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RotatingFileWriter implements log file rotation based on size and time
type RotatingFileWriter struct {
	mu          sync.Mutex
	file        *os.File
	filename    string
	maxSize     int64
	maxBackups  int
	maxAge      int
	currentSize int64
	lastRotate  time.Time
}

// Write implements the io.Writer interface and handles automatic log rotation
func (w *RotatingFileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.shouldRotate(int64(len(p))) {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}

	n, err = w.file.Write(p)
	w.currentSize += int64(n)

	return n, err
}

// Close closes the log file
func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		return w.file.Close()
	}

	return nil
}

// shouldRotate determines if log rotation should occur
func (w *RotatingFileWriter) shouldRotate(writeSize int64) bool {
	if w.maxSize > 0 && w.currentSize+writeSize > w.maxSize {
		return true
	}

	if time.Since(w.lastRotate) > 24*time.Hour {
		return true
	}

	return false
}

// rotate performs the log file rotation
func (w *RotatingFileWriter) rotate() error {
	// Close current file
	if w.file != nil {
		w.file.Close()
	}

	// Rename current file to backup
	backupName := w.backupName()
	if err := os.Rename(w.filename, backupName); err != nil && !os.IsNotExist(err) {
		return err
	}

	// Open new file
	if err := w.openFile(); err != nil {
		return err
	}

	w.lastRotate = time.Now()

	// Clean up old backup files
	w.cleanupBackups()

	return nil
}

// openFile opens the log file for writing
func (w *RotatingFileWriter) openFile() error {
	file, err := os.OpenFile(w.filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		return err
	}

	// Get current file size
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}

	w.file = file
	w.currentSize = info.Size()

	return nil
}

// backupName generates a backup file name with timestamp
func (w *RotatingFileWriter) backupName() string {
	dir := filepath.Dir(w.filename)
	base := filepath.Base(w.filename)
	ext := filepath.Ext(base)
	name := base[:len(base)-len(ext)]

	timestamp := time.Now().Format("20060102-150405")

	return filepath.Join(dir, fmt.Sprintf("%s-%s%s", name, timestamp, ext))
}

// cleanupBackups removes old backup files based on retention policies
func (w *RotatingFileWriter) cleanupBackups() {
	dir := filepath.Dir(w.filename)
	base := filepath.Base(w.filename)
	ext := filepath.Ext(base)
	name := base[:len(base)-len(ext)]

	pattern := filepath.Join(dir, fmt.Sprintf("%s-*%s", name, ext))

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}

	// Sort by modification time
	type fileInfo struct {
		path    string
		modTime time.Time
	}

	files := make([]fileInfo, 0, len(matches))
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			continue
		}

		files = append(files, fileInfo{
			path:    match,
			modTime: info.ModTime(),
		})
	}

	if w.maxBackups > 0 && len(files) > w.maxBackups {
		// Sort by time and keep only the newest backups
		for i := range len(files) - w.maxBackups {
			os.Remove(files[i].path)
		}
	}

	// Remove files exceeding the maximum age
	if w.maxAge > 0 {
		cutoff := time.Now().AddDate(0, 0, -w.maxAge)
		for _, f := range files {
			if f.modTime.Before(cutoff) {
				os.Remove(f.path)
			}
		}
	}
}

// cleanupOldFiles periodically cleans up old log files
func (w *RotatingFileWriter) cleanupOldFiles() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		w.mu.Lock()
		w.cleanupBackups()
		w.mu.Unlock()
	}
}

// MultiWriter writes to multiple output destinations simultaneously
type MultiWriter struct {
	writers []io.Writer
}

// NewMultiWriter creates a new multi-output writer
func NewMultiWriter(writers ...io.Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

// Write implements the io.Writer interface
func (mw *MultiWriter) Write(p []byte) (n int, err error) {
	for _, w := range mw.writers {
		n, err = w.Write(p)
		if err != nil {
			return n, err
		}
	}

	return len(p), nil
}
