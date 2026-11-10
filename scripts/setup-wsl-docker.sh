#!/usr/bin/env bash
# One-time dev setup inside WSL2 Ubuntu: Docker Engine for the Phase 0 slice.
# Uses Ubuntu's own packages (no third-party apt repo). Run as your normal user;
# it asks for your sudo password.
set -euo pipefail

sudo apt-get update
sudo apt-get install -y docker.io docker-buildx
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"

echo
echo "Docker installed: $(docker --version)"
echo "Close this terminal, then from Windows run:  wsl --terminate Ubuntu"
echo "so your user picks up the 'docker' group."
