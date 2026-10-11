# systemd User Service Unit for quarantine-daemon

This directory contains the systemd user service unit for running `quarantined` in the user session.

## Installation

1. Build or install the binary into `~/.local/bin/quarantined`:
   ```bash
   go build -o ~/.local/bin/quarantined ./cmd/quarantined
   chmod +x ~/.local/bin/quarantined
   ```

2. Copy the unit file into your user systemd directory:
   ```bash
   mkdir -p ~/.config/systemd/user
   cp systemd/quarantined.service ~/.config/systemd/user/
   ```

3. Reload systemd and enable the service:
   ```bash
   systemctl --user daemon-reload
   systemctl --user enable --now quarantined
   ```

## Management & Inspection

- Check service status:
  ```bash
  systemctl --user status quarantined
  ```

- Stream logs:
  ```bash
  journalctl --user -u quarantined -f
  ```

- Stop or restart service:
  ```bash
  systemctl --user stop quarantined
  systemctl --user restart quarantined
  ```

## Security Hardening Profile

The unit file applies the following security sandboxing directives:

- `ProtectSystem=strict`: Mounts `/usr`, `/boot`, `/etc` as read-only.
- `ProtectHome=read-only`: Mounts `/home`, `/root`, `/run/user` read-only by default.
- `ReadWritePaths=%h/Downloads /tmp %h/.local/share/quarantined %t`: Explicitly allows write access to monitored directories (`~/Downloads`, `/tmp`), quarantine storage (`~/.local/share/quarantined`), and the IPC runtime directory (`%t` / `$XDG_RUNTIME_DIR`).
- `PrivateTmp=false`: Preserves access to the host `/tmp` directory to allow detecting threats dropped during build or download operations.
- `NoNewPrivileges=true`: Prevents gaining additional privileges (disables SUID execution).
- `LockPersonality=true`: Locks the execution domain to avoid personality changes.
- `RestrictRealtime=true`: Refuses real-time scheduling requests.
- `RestrictNamespaces=true`: Restricts unprivileged namespace creation.
