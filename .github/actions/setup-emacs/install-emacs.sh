#!/usr/bin/env bash
set -euo pipefail

if command -v emacs >/dev/null 2>&1; then
  echo "Emacs already available; skipping setup."
  emacs --version | head -n 1
  exit 0
fi

cache_dir="${HOME}/.cache/org-ci/emacs-apt-archives"
mkdir -p "${cache_dir}/partial"

install_from_archives() {
  (
    cd "${cache_dir}"
    shopt -s nullglob
    local archives=(./*.deb)

    if [ "${#archives[@]}" -eq 0 ]; then
      return 1
    fi

    sudo apt-get install -y --no-download --no-install-recommends "${archives[@]}"
  )
}

if [ "${EMACS_CACHE_HIT:-false}" = "true" ]; then
  echo "Emacs package cache hit; restoring from cached archives."
else
  echo "Emacs package cache miss; downloading archives."
fi

if ! install_from_archives; then
  find "${cache_dir}" -maxdepth 1 -type f -name '*.deb' -delete
  sudo apt-get update
  sudo apt-get -o Dir::Cache::archives="${cache_dir}" install -y --no-install-recommends emacs-nox
  sudo chown -R "$(id -u):$(id -g)" "${cache_dir}"
fi

emacs --version | head -n 1
