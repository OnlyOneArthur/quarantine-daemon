// Package watcher monitors configured root directories with fsnotify and emits
// debounced file events for the scan pipeline.
package watcher

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Event represents a file notification dispatched by the watcher.
type Event struct {
	Path      string
	Immediate bool
}

// Config defines the configuration for the Watcher.
type Config struct {
	Roots            []string
	IgnoreExtensions []string
	DebounceDelay    time.Duration
}

type debounceItem struct {
	timer      *time.Timer
	generation uint64
}

// Watcher provides recursive filesystem monitoring with automatic subdirectory
// registration, cross-platform debouncing, and queue overflow reconciliation.
type Watcher struct {
	fsWatcher     *fsnotify.Watcher
	roots         []string
	ignoreExts    map[string]struct{}
	debounceDelay time.Duration

	events chan Event
	errors chan error

	mu          sync.Mutex
	watchedDirs map[string]struct{}
	timers      map[string]*debounceItem
	generation  uint64
	closed      bool

	reconcileCh chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// New creates and initializes a new recursive Watcher.
func New(cfg Config) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}

	delay := cfg.DebounceDelay
	if delay <= 0 {
		delay = 300 * time.Millisecond
	}

	ctx, cancel := context.WithCancel(context.Background())
	w := &Watcher{
		fsWatcher:     fsw,
		roots:         append([]string(nil), cfg.Roots...),
		ignoreExts:    parseIgnoreExtensions(cfg.IgnoreExtensions),
		debounceDelay: delay,
		events:        make(chan Event, 1024),
		errors:        make(chan error, 128),
		watchedDirs:   make(map[string]struct{}),
		timers:        make(map[string]*debounceItem),
		reconcileCh:   make(chan struct{}, 1),
		ctx:           ctx,
		cancel:        cancel,
	}

	for _, root := range cfg.Roots {
		if err := w.addRecursive(filepath.Clean(root)); err != nil {
			_ = w.Close()
			return nil, fmt.Errorf("initial watch root %s: %w", root, err)
		}
	}

	w.wg.Add(2)
	go w.eventLoop()
	go w.reconcileLoop()

	return w, nil
}

func parseIgnoreExtensions(exts []string) map[string]struct{} {
	ignoreMap := make(map[string]struct{})
	for _, ext := range exts {
		if ext != "" {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			ignoreMap[strings.ToLower(ext)] = struct{}{}
		}
	}
	return ignoreMap
}

// Events returns the channel of debounced file events.
func (w *Watcher) Events() <-chan Event {
	return w.events
}

// Errors returns the channel of watcher errors.
func (w *Watcher) Errors() <-chan error {
	return w.errors
}

// WatchedDirectories returns a snapshot of the directories currently watched.
func (w *Watcher) WatchedDirectories() []string {
	w.mu.Lock()
	defer w.mu.Unlock()

	dirs := make([]string, 0, len(w.watchedDirs))
	for d := range w.watchedDirs {
		dirs = append(dirs, d)
	}
	return dirs
}

// Close stops the watcher, joining its background goroutines and releasing
// every inotify watch.
func (w *Watcher) Close() error {
	// Wake any sender waiting on a full channel before taking the mutex.
	w.cancel()
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true

	for _, item := range w.timers {
		if item.timer.Stop() {
			w.wg.Done()
		}
	}
	w.timers = make(map[string]*debounceItem)
	w.mu.Unlock()

	err := w.fsWatcher.Close()
	w.wg.Wait()

	close(w.events)
	close(w.errors)

	return err
}

// AddRoot starts watching path and its non-hidden descendants. It returns an
// error if path does not exist.
func (w *Watcher) AddRoot(path string) error {
	cleanPath := filepath.Clean(path)

	// Validate before touching w.roots so a typo'd or missing path fails loudly
	// for the user-facing "watch this path" action. addRecursive stays lenient
	// because the reconcile walk and startup legitimately see vanished paths.
	if _, err := os.Lstat(cleanPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("watch path does not exist: %s", cleanPath)
		}
		return err
	}

	w.mu.Lock()
	if !slices.Contains(w.roots, cleanPath) {
		w.roots = append(w.roots, cleanPath)
	}
	w.mu.Unlock()

	return w.addRecursive(cleanPath)
}

func (w *Watcher) addRecursive(root string) error {
	return w.walkTree(root, nil)
}

// walkTree watches every non-hidden directory under root and, when onFile is
// non-nil, reports every non-directory entry. A single traversal serves both
// directory registration and initial file scanning, avoiding a second full walk
// of the same tree.
func (w *Watcher) walkTree(root string, onFile func(string)) error {
	info, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if !info.IsDir() {
		if onFile != nil {
			onFile(filepath.Clean(root))
		}
		return w.watchDir(root)
	}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip entries that vanished or are unreadable rather than aborting
			// the whole walk.
			return nil //nolint:nilerr // intentional: skip unreadable entries
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != root {
				return filepath.SkipDir
			}
			return w.watchDir(path)
		}
		if onFile != nil {
			onFile(filepath.Clean(path))
		}
		return nil
	})
}

func (w *Watcher) watchDir(dir string) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	if _, ok := w.watchedDirs[dir]; ok {
		w.mu.Unlock()
		return nil
	}
	w.watchedDirs[dir] = struct{}{}
	w.mu.Unlock()

	if err := w.fsWatcher.Add(dir); err != nil {
		w.mu.Lock()
		delete(w.watchedDirs, dir)
		w.mu.Unlock()
		return err
	}

	return nil
}

func (w *Watcher) unwatchDir(dir string) {
	w.mu.Lock()
	// filepath.Separator is already the final byte when dir is a filesystem
	// root (e.g. "/"), so avoid producing a "//" prefix that matches nothing.
	prefix := dir
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	toRemove := []string{dir}
	delete(w.watchedDirs, dir)
	for d := range w.watchedDirs {
		if strings.HasPrefix(d, prefix) {
			toRemove = append(toRemove, d)
			delete(w.watchedDirs, d)
		}
	}
	w.mu.Unlock()

	for _, d := range toRemove {
		_ = w.fsWatcher.Remove(d)
	}
}
