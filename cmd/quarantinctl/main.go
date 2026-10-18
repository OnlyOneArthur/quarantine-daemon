package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/ipc"
	"github.com/OnlyOneArthur/quarantine-daemon/internal/tui"
)

const Version = "0.1.0-dev"

func usage() {
	fmt.Fprintf(os.Stderr, `quarantinctl - command-line control for the quarantine daemon

Usage:
  quarantinctl [global options] <command> [command options] [arguments]

Commands:
  status                Show daemon running status and statistics
  list                  List all quarantined items in the vault
  inspect <id>          Show detailed threat report for a quarantined item
  restore <id> [--to P] Restore an item to its original path or destination
  purge <id>            Permanently delete an item from the vault
  watch add <path>      Dynamically add a directory to watch list
  tui                   Launch the interactive terminal UI
  version               Display version information

Global Options:
  --socket PATH         Path to daemon UNIX socket
  --config PATH         Path to configuration file
  --timeout DURATION    Request timeout (default: 5s)
  --json                Output results in JSON format
  -h, --help            Show this help
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(0)
	}

	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" || arg == "help" {
			usage()
			os.Exit(0)
		}
	}

	// Top-level flags
	globalFlags := flag.NewFlagSet("quarantinctl", flag.ContinueOnError)
	socketPath := globalFlags.String("socket", "", "path to daemon UNIX socket")
	configPath := globalFlags.String("config", "", "path to config.toml")
	timeout := globalFlags.Duration("timeout", 5*time.Second, "command timeout")
	jsonOutput := globalFlags.Bool("json", false, "output in JSON format")

	// Parse global flags until first non-flag arg
	if err := globalFlags.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}

	args := globalFlags.Args()
	if len(args) == 0 {
		usage()
		os.Exit(0)
	}

	cmd := args[0]
	cmdArgs := args[1:]

	if cmd == "version" || cmd == "--version" || cmd == "-v" {
		fmt.Printf("quarantinctl %s\n", Version)
		return
	}
	if cmd == "help" || cmd == "--help" || cmd == "-h" {
		usage()
		return
	}

	resolvedSocket := resolveSocket(*socketPath, *configPath)

	if cmd == "tui" {
		if err := tui.Run(tui.SocketDialer(resolvedSocket), Version); err != nil {
			fmt.Fprintf(os.Stderr, "tui failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	client, err := ipc.NewClient(resolvedSocket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to daemon at %s: %v\n", resolvedSocket, err)
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var cmdErr error
	switch cmd {
	case "status":
		cmdErr = handleStatus(ctx, client, *jsonOutput)
	case "list":
		cmdErr = handleList(ctx, client, *jsonOutput)
	case "inspect":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "error: inspect requires an item <id>")
			os.Exit(1)
		}
		cmdErr = handleInspect(ctx, client, cmdArgs[0], *jsonOutput)
	case "restore":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "error: restore requires an item <id> [--to <dest>]")
			os.Exit(1)
		}
		dest := ""
		for i := 1; i < len(cmdArgs); i++ {
			if (cmdArgs[i] == "--to" || cmdArgs[i] == "-to") && i+1 < len(cmdArgs) {
				dest = cmdArgs[i+1]
				break
			}
		}
		cmdErr = handleRestore(ctx, client, cmdArgs[0], dest)
	case "purge":
		if len(cmdArgs) < 1 {
			fmt.Fprintln(os.Stderr, "error: purge requires an item <id>")
			os.Exit(1)
		}
		cmdErr = handlePurge(ctx, client, cmdArgs[0])
	case "watch":
		if len(cmdArgs) < 2 || cmdArgs[0] != "add" {
			fmt.Fprintln(os.Stderr, "usage: quarantinctl watch add <path>")
			os.Exit(1)
		}
		cmdErr = handleWatchAdd(ctx, client, cmdArgs[1])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q (run 'quarantinctl --help' for usage)\n", cmd)
		os.Exit(1)
	}

	if cmdErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", cmdErr)
		os.Exit(1)
	}
}

func resolveSocket(socketFlag, configFlag string) string {
	if socketFlag != "" {
		return socketFlag
	}
	cfg, err := config.Load(configFlag)
	if err == nil && cfg.Service.SocketPath != "" {
		return cfg.Service.SocketPath
	}
	// Default fallback
	runDir := os.Getenv("XDG_RUNTIME_DIR")
	if runDir == "" {
		return filepath.Join(os.TempDir(), fmt.Sprintf("quarantined-%d", os.Getuid()), "quarantined.sock")
	}
	return filepath.Join(runDir, "quarantined", "quarantined.sock")
}

func handleStatus(ctx context.Context, client *ipc.Client, asJSON bool) error {
	st, err := client.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("daemon connection failed: %w", err)
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}

	uptime := time.Duration(st.Uptime) * time.Second
	fmt.Printf("quarantined daemon %s\n", st.Version)
	fmt.Printf("  Uptime:       %s\n", uptime.Round(time.Second))
	fmt.Printf("  Scanned:      %d files\n", st.ScannedCount)
	fmt.Printf("  Quarantined:  %d files\n", st.QuarantineCount)
	fmt.Printf("  Watch Paths:\n")
	for _, p := range st.WatchPaths {
		fmt.Printf("    • %s\n", p)
	}
	return nil
}

func handleList(ctx context.Context, client *ipc.Client, asJSON bool) error {
	items, err := client.ListVault(ctx)
	if err != nil {
		return fmt.Errorf("list vault: %w", err)
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(items)
	}

	if len(items) == 0 {
		fmt.Println("Vault is empty. No quarantined items.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSCORE\tQUARANTINED AT\tSIZE\tORIGINAL PATH")
	for _, item := range items {
		shortID := item.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%d B\t%s\n",
			shortID,
			item.Score,
			item.QuarantinedAt.Local().Format("2006-01-02 15:04:05"),
			item.Size,
			item.OriginalPath,
		)
	}
	return w.Flush()
}

func handleInspect(ctx context.Context, client *ipc.Client, id string, asJSON bool) error {
	item, err := client.InspectItem(ctx, id)
	if err != nil {
		return fmt.Errorf("inspect item %q: %w", id, err)
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(item)
	}

	fmt.Printf("Quarantine Item: %s\n", item.ID)
	fmt.Printf("  Original Path:  %s\n", item.OriginalPath)
	fmt.Printf("  SHA256:         %s\n", item.SHA256)
	fmt.Printf("  Size:           %d bytes\n", item.Size)
	fmt.Printf("  Quarantined At: %s\n", item.QuarantinedAt.Local().Format(time.RFC3339))
	fmt.Printf("  Threat Score:   %d / 100\n", item.Score)
	fmt.Printf("  Is PKGBUILD:    %v\n", item.IsPKGBUILD)

	if len(item.CategoriesHit) > 0 {
		fmt.Printf("  Categories:     %v\n", item.CategoriesHit)
	}
	if len(item.Triggers) > 0 {
		fmt.Println("  Triggers:")
		for _, trig := range item.Triggers {
			fmt.Printf("    • %s\n", trig)
		}
	}
	if len(item.DampenersApplied) > 0 {
		fmt.Println("  Dampeners Applied:")
		for _, damp := range item.DampenersApplied {
			fmt.Printf("    • %s\n", damp)
		}
	}
	return nil
}

func handleRestore(ctx context.Context, client *ipc.Client, id, dest string) error {
	if err := client.RestoreItem(ctx, id, dest); err != nil {
		return fmt.Errorf("restore item %q: %w", id, err)
	}
	if dest != "" {
		fmt.Printf("Successfully restored item %s to %s\n", id, dest)
	} else {
		fmt.Printf("Successfully restored item %s to original location\n", id)
	}
	return nil
}

func handlePurge(ctx context.Context, client *ipc.Client, id string) error {
	if err := client.PurgeItem(ctx, id); err != nil {
		return fmt.Errorf("purge item %q: %w", id, err)
	}
	fmt.Printf("Successfully purged item %s from vault\n", id)
	return nil
}

func handleWatchAdd(ctx context.Context, client *ipc.Client, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve path %q: %w", path, err)
	}
	if err := client.AddWatchPath(ctx, abs); err != nil {
		return fmt.Errorf("add watch path %q: %w", abs, err)
	}
	fmt.Printf("Successfully added watch path: %s\n", abs)
	return nil
}
