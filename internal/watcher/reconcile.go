package watcher

import (
	"fmt"
	"path/filepath"
)

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

// ReconcileWalk re-registers every configured root, recovering watches lost to
// inotify limits or overflow events.
func (w *Watcher) ReconcileWalk() error {
	w.mu.Lock()
	roots := append([]string(nil), w.roots...)
	w.mu.Unlock()

	for _, root := range roots {
		cleanRoot := filepath.Clean(root)
		if err := w.walkTree(cleanRoot, w.dispatchFileEvent); err != nil {
			return fmt.Errorf("reconcile root %s: %w", cleanRoot, err)
		}
	}
	return nil
}
