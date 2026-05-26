#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

# ── Dependencies ─────────────────────────────────────────────
for cmd in git python3 pip3; do
    command -v "$cmd" &>/dev/null || {
        warn "Installing missing packages..."
        sudo apt-get update -qq
        sudo apt-get install -y git python3 python3-pip
        break
    }
done

# ── PATH ─────────────────────────────────────────────────────
export PATH="$HOME/.local/bin:$PATH"
grep -q '\.local/bin' "$HOME/.bashrc" 2>/dev/null || \
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"

# ── Remove ALL conflicting aliases ───────────────────────────
for tool in sqlmap ghauri; do
    unalias "$tool" 2>/dev/null || true
    for cfg in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.bash_aliases" \
               "$HOME/.zsh_aliases" "$HOME/.profile" "$HOME/.bash_profile"; do
        [[ -f "$cfg" ]] && sed -i "/alias ${tool}=/d" "$cfg" 2>/dev/null || true
    done
done

# ── sqlmap ───────────────────────────────────────────────────
info "Setting up sqlmap..."
if [[ -d "$HOME/sqlmap/.git" ]]; then
    git -C "$HOME/sqlmap" pull --quiet
else
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$HOME/sqlmap"
fi
python3 "$HOME/sqlmap/sqlmap.py" --version &>/dev/null || error "sqlmap failed"
info "sqlmap OK → python3 ~/sqlmap/sqlmap.py"

# ── ghauri ───────────────────────────────────────────────────
info "Setting up ghauri..."
if [[ -d "$HOME/ghauri/.git" ]]; then
    git -C "$HOME/ghauri" pull --quiet
else
    git clone --depth 1 https://github.com/r0oth3x49/ghauri.git "$HOME/ghauri"
fi

pip3 install --quiet --break-system-packages "$HOME/ghauri" 2>/dev/null || \
pip3 install --quiet "$HOME/ghauri" 2>/dev/null || \
    error "ghauri pip install failed"

[[ -f "$HOME/.local/bin/ghauri" ]] || error "ghauri binary not found after install"
info "ghauri OK → ~/.local/bin/ghauri"

# ── Done ─────────────────────────────────────────────────────
echo ""
info "All done! Run: source ~/.bashrc"
echo ""
echo "  sqlmap -u 'http://target/?id=1' --dbs"
echo "  ghauri -u 'http://target/?id=1' --dbs"
echo ""
