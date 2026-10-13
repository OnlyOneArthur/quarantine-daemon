package watcher

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
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

	ignoreMap := make(map[string]struct{})
	for _, ext := range cfg.IgnoreExtensions {
		if ext != "" {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			ignoreMap[strings.ToLower(ext)] = struct{}{}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	w := &Watcher{
		fsWatcher:     fsw,
		roots:         append([]string(nil), cfg.Roots...),
		ignoreExts:    ignoreMap,
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

func (w *Watcher) Events() <-chan Event {
	return w.events
}

func (w *Watcher) Errors() <-chan error {
	return w.errors
}

func (w *Watcher) WatchedDirectories() []string {
	w.mu.Lock()
	defer w.mu.Unlock()

	dirs := make([]string, 0, len(w.watchedDirs))
	for d := range w.watchedDirs {
		dirs = append(dirs, d)
	}
	return dirs
}

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
	alreadyExists := false
	for _, r := range w.roots {
		if r == cleanPath {
			alreadyExists = true
			break
		}
	}
	if !alreadyExists {
		w.roots = append(w.roots, cleanPath)
	}
	w.mu.Unlock()

	return w.addRecursive(cleanPath)
}

func (w *Watcher) addRecursive(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if !info.IsDir() {
		return w.watchDir(root)
	}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != root {
				return filepath.SkipDir
			}
			return w.watchDir(path)
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
	prefix := dir + string(filepath.Separator)
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

func (w *Watcher) eventLoop() {
	defer w.wg.Done()

	for {
		select {
		case <-w.ctx.Done():
			return

		case ev, ok := <-w.fsWatcher.Events:
			if !ok {
				return
			}
			w.handleFsEvent(ev)

		case err, ok := <-w.fsWatcher.Errors:
			if !ok {
				return
			}
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				w.triggerReconcile()
			} else {
				w.sendError(err)
			}
		}
	}
}

func (w *Watcher) handleFsEvent(ev fsnotify.Event) {
	cleanPath := filepath.Clean(ev.Name)

	if ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
		// Remove/Rename identify the old path; cancel pending work instead of
		// emitting an event for a file that no longer exists there.
		w.cancelDebounce(cleanPath)
		w.mu.Lock()
		_, isWatched := w.watchedDirs[cleanPath]
		w.mu.Unlock()
		if isWatched {
			w.unwatchDir(cleanPath)
			return
		}
	}

	if ev.Op&fsnotify.Create != 0 {
		info, err := os.Lstat(cleanPath)
		if err == nil && info.IsDir() {
			if addErr := w.addRecursive(cleanPath); addErr != nil {
				w.sendError(addErr)
			}
			_ = filepath.WalkDir(cleanPath, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() && path != cleanPath && strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				if !d.IsDir() {
					w.dispatchFileEvent(filepath.Clean(path))
				}
				return nil
			})
			return
		}
	}

	if ev.Op&(fsnotify.Create|fsnotify.Write) != 0 {
		w.dispatchFileEvent(cleanPath)
	}
}

func (w *Watcher) isIgnored(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	_, ignored := w.ignoreExts[ext]
	return ignored
}

func (w *Watcher) isImmediate(path string) bool {
	base := filepath.Base(path)
	if base == "PKGBUILD" || strings.HasSuffix(base, ".install") {
		return true
	}
	return false
}

func (w *Watcher) dispatchFileEvent(path string) {
	if w.isIgnored(path) {
		return
	}

	if w.isImmediate(path) {
		w.cancelDebounce(path)
		w.emitEvent(Event{
			Path:      path,
			Immediate: true,
		})
		return
	}

	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}

	if item, exists := w.timers[path]; exists {
		if item.timer.Stop() {
			w.wg.Done()
		}
	}

	w.generation++
	gen := w.generation

	w.wg.Add(1)
	t := time.AfterFunc(w.debounceDelay, func() {
		defer w.wg.Done()
		w.onDebounceTimerFired(path, gen)
	})

	w.timers[path] = &debounceItem{
		timer:      t,
		generation: gen,
	}
	w.mu.Unlock()
}

func (w *Watcher) cancelDebounce(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if item, exists := w.timers[path]; exists {
		if item.timer.Stop() {
			w.wg.Done()
		}
		delete(w.timers, path)
	}
}

func (w *Watcher) onDebounceTimerFired(path string, gen uint64) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	item, exists := w.timers[path]
	if !exists || item.generation != gen {
		w.mu.Unlock()
		return
	}
	delete(w.timers, path)
	w.mu.Unlock()

	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}

	if !w.waitForFileReady(path) {
		return
	}

	w.emitEvent(Event{
		Path:      path,
		Immediate: false,
	})
}

func (w *Watcher) waitForFileReady(path string) bool {
	backoff := 10 * time.Millisecond
	totalWait := time.Duration(0)
	maxWait := 500 * time.Millisecond

	for {
		select {
		case <-w.ctx.Done():
			return false
		default:
		}

		sf, err := fsutil.OpenSafe(path)
		if err == nil {
			_ = sf.Close()
			return true
		}

		if totalWait >= maxWait {
			return false
		}

		select {
		case <-w.ctx.Done():
			return false
		case <-time.After(backoff):
			totalWait += backoff
			backoff *= 2
			if backoff > 100*time.Millisecond {
				backoff = 100 * time.Millisecond
			}
		}
	}
}

func (w *Watcher) emitEvent(ev Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	// Keep the channel open through the send; Close cancels before taking mu.
	select {
	case <-w.ctx.Done():
	case w.events <- ev:
	}
}

func (w *Watcher) sendError(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	select {
	case <-w.ctx.Done():
	case w.errors <- err:
	}
}

func (w *Watcher) triggerReconcile() {
	select {
	case w.reconcileCh <- struct{}{}:
	default:
	}
}

func (w *Watcher) reconcileLoop() {
	defer w.wg.Done()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-w.reconcileCh:
			if err := w.ReconcileWalk(); err != nil {
				w.sendError(err)
			}
		}
	}
}

func (w *Watcher) ReconcileWalk() error {
	w.mu.Lock()
	roots := append([]string(nil), w.roots...)
	w.mu.Unlock()

	for _, root := range roots {
		cleanRoot := filepath.Clean(root)
		if err := w.addRecursive(cleanRoot); err != nil {
			return fmt.Errorf("reconcile root %s: %w", cleanRoot, err)
		}
		_ = filepath.WalkDir(cleanRoot, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() && path != cleanRoot && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			if !d.IsDir() {
				w.dispatchFileEvent(filepath.Clean(path))
			}
			return nil
		})
	}
	return nil
}
