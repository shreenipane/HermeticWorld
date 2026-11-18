#!/usr/bin/env bash
# One-time dev setup inside WSL2 Ubuntu: Docker Engine for the Phase 0 slice.
# Uses Ubuntu's own packages (no third-party apt repo). Run as your normal user;
# it asks for your sudo password.
set -euo pipefail

# systemctl needs systemd as PID 1; WSL init is not enough. Check before installing anything.
if [ ! -d /run/systemd/system ]; then
  echo "systemd is not running in this WSL instance." >&2
  echo "Add the following to /etc/wsl.conf, run 'wsl --shutdown' from Windows, then rerun:" >&2
  printf '  [boot]\n  systemd=true\n' >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y docker.io docker-buildx
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"

echo
echo "Docker installed: $(docker --version)"
echo "Close this terminal, then from Windows run:  wsl --terminate Ubuntu"
echo "so your user picks up the 'docker' group."
