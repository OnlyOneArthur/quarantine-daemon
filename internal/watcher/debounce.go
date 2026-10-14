package watcher

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/fsutil"
	"github.com/fsnotify/fsnotify"
)

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
			// Startup and reconcile walks deliberately skip hidden directories
			// (.git, .cache, node_modules caches). A directory created at runtime
			// must not bypass that filter and drag its whole tree into the scan
			// pipeline.
			if w.isHiddenNonRootDir(cleanPath) {
				return
			}
			if addErr := w.walkTree(cleanPath, w.dispatchFileEvent); addErr != nil {
				w.sendError(addErr)
			}
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

// isHiddenNonRootDir reports whether path is a hidden directory that is not an
// explicitly configured watch root. Watch roots may legitimately be hidden
// (e.g. ~/.config), so they are always allowed.
func (w *Watcher) isHiddenNonRootDir(path string) bool {
	if !strings.HasPrefix(filepath.Base(path), ".") {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, root := range w.roots {
		if filepath.Clean(root) == path {
			return false
		}
	}
	return true
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

	timer := time.NewTimer(backoff)
	defer timer.Stop()

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
		case <-timer.C:
			totalWait += backoff
			backoff *= 2
			if backoff > 100*time.Millisecond {
				backoff = 100 * time.Millisecond
			}
			timer.Reset(backoff)
		}
	}
}

func (w *Watcher) emitEvent(ev Event) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.mu.Unlock()

	select {
	case <-w.ctx.Done():
	case w.events <- ev:
	}
}

func (w *Watcher) sendError(err error) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.mu.Unlock()

	select {
	case <-w.ctx.Done():
	case w.errors <- err:
	}
}
