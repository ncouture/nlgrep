#!/usr/bin/env bash
set -euo pipefail

if command -v emacs >/dev/null 2>&1; then
  echo "Emacs already available; skipping setup."
  emacs --version | head -n 1
  exit 0
fi

cache_dir="${HOME}/.cache/org-ci/emacs-apt-archives"
apt_cache_dir=/var/cache/apt/archives

mkdir -p "${cache_dir}"

install_from_archives() {
  local archives=()

  while IFS= read -r -d '' archive; do
    archives+=("${archive}")
  done < <(find "${cache_dir}" -maxdepth 1 -type f -name '*.deb' -print0 | sort -z)

  if [ "${#archives[@]}" -eq 0 ]; then
    return 1
  fi

  sudo apt-get install -y --no-download --no-install-recommends "${archives[@]}"
}

if [ "${EMACS_CACHE_HIT:-false}" = "true" ]; then
  echo "Emacs package cache hit; restoring from cached archives."
else
  echo "Emacs package cache miss; downloading archives."
fi

if ! install_from_archives; then
  sudo apt-get update
  sudo apt-get install -y --download-only --no-install-recommends emacs-nox
  find "${apt_cache_dir}" -maxdepth 1 -type f -name '*.deb' -exec cp -f {} "${cache_dir}/" \;
  install_from_archives
fi

emacs --version | head -n 1
