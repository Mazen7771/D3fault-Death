#!/usr/bin/env bash

set -u

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

TOOLS_DIR="$HOME/tools"
GO_BIN="$HOME/go/bin"
VENV="$PROJECT_DIR/env"

TESTSSL_DIR="$TOOLS_DIR/testssl_tool"
JWT_DIR="$TOOLS_DIR/jwt_tool"
PARAMSPIDER_DIR="$TOOLS_DIR/ParamSpider"
CMSMAP_DIR="$TOOLS_DIR/CMSmap"
LINKFINDER_DIR="$TOOLS_DIR/LinkFinder"
TPLMAP_DIR="$TOOLS_DIR/tplmap"
CLOUDENUM_DIR="$TOOLS_DIR/cloud_enum"
GRAPHW00F_DIR="$TOOLS_DIR/graphw00f"
RACETHEWEB_DIR="$TOOLS_DIR/race-the-web"
BURP_DIR="$TOOLS_DIR/burp-extensions"

NUCLEI_DIR="$HOME/.local/share/nuclei-templates"

export PATH="$GO_BIN:$VENV/bin:$PATH"

FAILED=()

ok() {
    printf '\033[1;32m[OK]\033[0m %s\n' "$1"
}

warn() {
    printf '\033[1;33m[WARN]\033[0m %s\n' "$1"
}

fail() {
    printf '\033[1;31m[FAILED]\033[0m %s\n' "$1"
    FAILED+=("$1")
}

section() {
    echo
    echo "============================================================"
    echo "$1"
    echo "============================================================"
}

apt_install() {
    local description="$1"
    shift

    echo "[+] $description"

    if sudo apt-get install -y "$@"; then
        ok "$description"
    else
        fail "$description"
    fi
}

pip_install() {
    local description="$1"
    shift

    echo "[+] $description"

    if "$VENV/bin/python" -m pip install "$@"; then
        ok "$description"
    else
        fail "$description"
    fi
}

clone_repo() {
    local url="$1"
    local dir="$2"
    local description="$3"

    echo "[+] $description"

    if [ -d "$dir/.git" ]; then
        git -C "$dir" fetch --depth 1 origin
        git -C "$dir" reset --hard origin/HEAD 2>/dev/null || true
        ok "$description (updated)"
        return 0
    fi

    if git clone --depth 1 "$url" "$dir"; then
        ok "$description"
    else
        fail "$description"
    fi
}

go_install() {
    local module="$1"

    echo "[+] go install $module"

    if GOBIN="$GO_BIN" go install "$module"; then
        ok "$(basename "${module%@*}")"
    else
        fail "Go: $module"
    fi
}

section "[1/9] SYSTEM / BOOTSTRAP"

sudo apt-get update || fail "apt update"

apt_install "Bootstrap packages" \
    ca-certificates \
    curl \
    wget \
    git \
    unzip \
    xz-utils \
    build-essential \
    pkg-config \
    libssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    golang-go

apt_install "Core reconnaissance packages" \
    jq \
    bind9-dnsutils \
    bind9-host \
    whois \
    nmap \
    masscan \
    whatweb \
    wafw00f \
    nikto \
    dnsrecon \
    dnsenum \
    massdns \
    gobuster \
    dirb \
    exploitdb \
    sqlmap \
    wpscan \
    seclists \
    amass \
    feroxbuster \
    terminator

section "[2/9] GO ENVIRONMENT"

mkdir -p "$GO_BIN"

if command -v go >/dev/null 2>&1; then
    ok "$(go version)"
else
    fail "Go compiler unavailable"
fi

if ! grep -Fq 'export PATH="$HOME/go/bin:$PATH"' "$HOME/.bashrc" 2>/dev/null; then
    printf '%s\n' 'export PATH="$HOME/go/bin:$PATH"' >> "$HOME/.bashrc"
fi

if [ -f "$HOME/.zshrc" ] && \
   ! grep -Fq 'export PATH="$HOME/go/bin:$PATH"' "$HOME/.zshrc" 2>/dev/null; then
    printf '%s\n' 'export PATH="$HOME/go/bin:$PATH"' >> "$HOME/.zshrc"
fi

section "[3/9] GO SECURITY / RECON TOOLS"

GO_TOOLS=(
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
    "github.com/projectdiscovery/notify/cmd/notify@latest"

    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/gron@latest"
    "github.com/tomnomnom/unew@latest"

    "github.com/lc/gau/v2/cmd/gau@latest"

    "github.com/ffuf/ffuf/v2@latest"
    "github.com/OJ/gobuster/v3@latest"

    "github.com/trufflesecurity/trufflehog/v3@latest"
    "github.com/zricethezav/gitleaks/v8@latest"

    "github.com/sensepost/gowitness@latest"
    "github.com/hahwul/dalfox/v2@latest"

    "github.com/haccer/subjack@latest"
    "github.com/LukaSikic/subzy@latest"

    "github.com/projectdiscovery/kiterunner/cmd/kr@latest"

    "github.com/anchore/grype/cmd/grype@latest"
    "github.com/anchore/syft/cmd/syft@latest"

    "github.com/nccgroup/wsrecon@latest"

    "github.com/BishopFox/jsluice/cmd/jsluice@latest"
    "github.com/brosck/mantra@latest"
)

for module in "${GO_TOOLS[@]}"; do
    go_install "$module"
done

section "[4/9] PYTHON VIRTUAL ENVIRONMENT"

if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV" || fail "Create Python virtual environment"
fi

source "$VENV/bin/activate"

"$VENV/bin/python" -m pip install --upgrade pip setuptools wheel \
    || fail "Upgrade pip/setuptools/wheel"

pip_install "Install requirements.txt" \
    -r "$PROJECT_DIR/requirements.txt"

section "[5/9] PYTHON SOURCE TOOLS"

mkdir -p "$TOOLS_DIR"

# ------------------------------------------------------------
# ParamSpider
# ------------------------------------------------------------

clone_repo \
    "https://github.com/devanshbatham/ParamSpider.git" \
    "$PARAMSPIDER_DIR" \
    "ParamSpider"

if [ -f "$PARAMSPIDER_DIR/requirements.txt" ]; then
    pip_install "ParamSpider dependencies" \
        -r "$PARAMSPIDER_DIR/requirements.txt"
fi

if [ -f "$PARAMSPIDER_DIR/setup.py" ] || \
   [ -f "$PARAMSPIDER_DIR/pyproject.toml" ]; then
    pip_install "Install ParamSpider" \
        "$PARAMSPIDER_DIR"
fi

# ------------------------------------------------------------
# CMSmap
# ------------------------------------------------------------

clone_repo \
    "https://github.com/Dionach/CMSmap.git" \
    "$CMSMAP_DIR" \
    "CMSmap"

if [ -f "$CMSMAP_DIR/requirements.txt" ]; then
    pip_install "CMSmap dependencies" \
        -r "$CMSMAP_DIR/requirements.txt"
fi

if [ -f "$CMSMAP_DIR/setup.py" ]; then
    pip_install "Install CMSmap" \
        "$CMSMAP_DIR"
fi

# ------------------------------------------------------------
# LinkFinder
# ------------------------------------------------------------

clone_repo \
    "https://github.com/GerbenJavado/LinkFinder.git" \
    "$LINKFINDER_DIR" \
    "LinkFinder"

if [ -f "$LINKFINDER_DIR/requirements.txt" ]; then
    pip_install "LinkFinder dependencies" \
        -r "$LINKFINDER_DIR/requirements.txt"
fi

if [ -f "$LINKFINDER_DIR/setup.py" ]; then
    pip_install "Install LinkFinder" \
        "$LINKFINDER_DIR"
fi

# ------------------------------------------------------------
# Tplmap
# ------------------------------------------------------------

clone_repo \
    "https://github.com/epinna/tplmap.git" \
    "$TPLMAP_DIR" \
    "Tplmap"

if [ -f "$TPLMAP_DIR/requirements.txt" ]; then
    pip_install "Tplmap dependencies" \
        -r "$TPLMAP_DIR/requirements.txt"
fi

# Tplmap is old and may require compatibility work on Python 3.13+.
# We still download and prepare it; verification reports source presence.

# ------------------------------------------------------------
# cloud_enum
# ------------------------------------------------------------

clone_repo \
    "https://github.com/initstring/cloud_enum.git" \
    "$CLOUDENUM_DIR" \
    "cloud_enum"

if [ -f "$CLOUDENUM_DIR/requirements.txt" ]; then
    pip_install "cloud_enum dependencies" \
        -r "$CLOUDENUM_DIR/requirements.txt"
fi

# ------------------------------------------------------------
# ghauri
# ------------------------------------------------------------

if "$VENV/bin/python" -m pip install ghauri; then
    ok "ghauri"
else
    warn "PyPI ghauri unavailable; trying upstream source"

    clone_repo \
        "https://github.com/r0oth3x49/ghauri.git" \
        "$TOOLS_DIR/ghauri" \
        "ghauri source"

    if [ -f "$TOOLS_DIR/ghauri/requirements.txt" ]; then
        pip_install "ghauri source dependencies" \
            -r "$TOOLS_DIR/ghauri/requirements.txt"
    fi

    pip_install "Install ghauri from source" \
        "$TOOLS_DIR/ghauri"
fi

# ------------------------------------------------------------
# graphw00f
# ------------------------------------------------------------

clone_repo \
    "https://github.com/dolevf/graphw00f.git" \
    "$GRAPHW00F_DIR" \
    "graphw00f"

if [ -f "$GRAPHW00F_DIR/requirements.txt" ]; then
    pip_install "graphw00f dependencies" \
        -r "$GRAPHW00F_DIR/requirements.txt"
fi

if [ -f "$GRAPHW00F_DIR/setup.py" ] || \
   [ -f "$GRAPHW00F_DIR/pyproject.toml" ]; then
    pip_install "Install graphw00f" \
        "$GRAPHW00F_DIR"
fi

section "[6/9] JWT TOOL"

clone_repo \
    "https://github.com/ticarpi/jwt_tool.git" \
    "$JWT_DIR" \
    "jwt_tool"

if [ -f "$JWT_DIR/requirements.txt" ]; then
    pip_install "jwt_tool dependencies" \
        -r "$JWT_DIR/requirements.txt"
else
    pip_install "jwt_tool dependencies" \
        termcolor \
        cprint \
        pycryptodomex \
        requests \
        ratelimit
fi

cat > "$GO_BIN/jwt_tool" <<SCRIPT
#!/usr/bin/env bash
exec "$VENV/bin/python" "$JWT_DIR/jwt_tool.py" "\$@"
SCRIPT

chmod +x "$GO_BIN/jwt_tool"
ok "jwt_tool wrapper"

section "[7/9] MANUAL / DATA RESOURCES"

mkdir -p "$TOOLS_DIR"

# ------------------------------------------------------------
# testssl.sh
# ------------------------------------------------------------

clone_repo \
    "https://github.com/drwetter/testssl.sh.git" \
    "$TESTSSL_DIR" \
    "testssl.sh"

if [ -f "$TESTSSL_DIR/testssl.sh" ]; then
    chmod +x "$TESTSSL_DIR/testssl.sh"
    ok "testssl.sh executable"
fi

# ------------------------------------------------------------
# SecLists
# ------------------------------------------------------------

if [ -d "/usr/share/seclists" ]; then
    ok "SecLists at /usr/share/seclists"
else
    warn "SecLists package path missing; cloning fallback"

    clone_repo \
        "https://github.com/danielmiessler/SecLists.git" \
        "$TOOLS_DIR/SecLists" \
        "SecLists fallback"

    if [ -d "$TOOLS_DIR/SecLists" ]; then
        sudo mkdir -p /usr/share/seclists
        sudo cp -a "$TOOLS_DIR/SecLists/." /usr/share/seclists/
        ok "SecLists copied to /usr/share/seclists"
    fi
fi

# ------------------------------------------------------------
# Nuclei templates
# ------------------------------------------------------------

mkdir -p "$NUCLEI_DIR"

if [ -x "$GO_BIN/nuclei" ]; then
    if "$GO_BIN/nuclei" \
        -update-templates \
        -ud "$NUCLEI_DIR"; then
        ok "Nuclei templates"
    else
        fail "Nuclei templates"
    fi
else
    fail "Nuclei binary missing; templates not installed"
fi

# ------------------------------------------------------------
# DNS resolvers
# ------------------------------------------------------------

mkdir -p "$PROJECT_DIR/config"

if curl -fL \
    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
    -o "$PROJECT_DIR/config/resolvers.txt"; then
    ok "DNS resolvers"
else
    fail "DNS resolvers"
fi

# ------------------------------------------------------------
# Subjack fingerprints
# ------------------------------------------------------------

mkdir -p "$HOME/.subjack"

if curl -fL \
    "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json" \
    -o "$HOME/.subjack/fingerprints.json"; then
    ok "Subjack fingerprints"
else
    fail "Subjack fingerprints"
fi

section "[8/9] BURP EXTENSIONS"

mkdir -p "$BURP_DIR"

clone_repo \
    "https://github.com/PortSwigger/auth-matrix.git" \
    "$BURP_DIR/AuthMatrix" \
    "AuthMatrix source"

clone_repo \
    "https://github.com/Quitten/Autorize.git" \
    "$BURP_DIR/Autorize" \
    "Autorize source"

echo
echo "Burp extensions prepared:"
echo "  $BURP_DIR/AuthMatrix/AuthMatrix.py"
echo "  $BURP_DIR/Autorize/Autorize.py"
echo
echo "These are Burp extensions, so they cannot be activated by pip."
echo "Load the corresponding .py file through Burp Extender."

section "[9/9] RACE-THE-WEB"

clone_repo \
    "https://github.com/TheHackerDev/race-the-web.git" \
    "$RACETHEWEB_DIR" \
    "Race-the-Web"

if [ -f "$RACETHEWEB_DIR/Makefile" ]; then
    (
        cd "$RACETHEWEB_DIR" &&
        make build
    )

    if [ -f "$RACETHEWEB_DIR/bin/race-the-web" ]; then
        cp "$RACETHEWEB_DIR/bin/race-the-web" "$GO_BIN/race-the-web"
        chmod +x "$GO_BIN/race-the-web"
        ok "Race-the-Web binary"
    else
        fail "Race-the-Web binary"
    fi
else
    fail "Race-the-Web Makefile missing"
fi

# ------------------------------------------------------------
# libpostal / Amass
# ------------------------------------------------------------

if command -v libpostal_data >/dev/null 2>&1; then
    sudo mkdir -p /var/lib/libpostal
    sudo mkdir -p /usr/share/libpostal

    if sudo libpostal_data download all /var/lib/libpostal; then
        ok "libpostal data"
    else
        warn "libpostal data download failed"
    fi

    if [ -e /var/lib/libpostal/transliteration ]; then
        sudo ln -sfn \
            /var/lib/libpostal/transliteration \
            /usr/share/libpostal/transliteration
        ok "libpostal transliteration link"
    fi
fi

section "VERIFICATION"

echo
echo "--- System binaries ---"

SYSTEM_BINARIES=(
    jq
    curl
    wget
    dig
    host
    whois
    nmap
    masscan
    massdns
    whatweb
    wafw00f
    nikto
    dnsrecon
    dnsenum
    gobuster
    dirb
    searchsploit
    sqlmap
    wpscan
    amass
    feroxbuster
    go
)

for tool in "${SYSTEM_BINARIES[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "$tool"
    else
        warn "$tool"
    fi
done

echo
echo "--- Go binaries ---"

GO_BINARIES=(
    dnsx
    naabu
    katana
    shuffledns
    chaos
    httpx
    nuclei
    subfinder
    alterx
    mapcidr
    notify
    assetfinder
    waybackurls
    gf
    anew
    gron
    unew
    gau
    ffuf
    gobuster
    trufflehog
    gitleaks
    gowitness
    dalfox
    subjack
    subzy
    kr
    grype
    syft
    wsrecon
    jsluice
    mantra
    race-the-web
    jwt_tool
)

for tool in "${GO_BINARIES[@]}"; do
    if [ -x "$GO_BIN/$tool" ]; then
        ok "$tool"
    else
        warn "$tool"
    fi
done

echo
echo "--- Python ---"

if [ -x "$VENV/bin/python" ]; then
    ok "Python virtual environment"
    "$VENV/bin/python" --version
else
    fail "Python virtual environment"
fi

if [ -x "$VENV/bin/pip" ]; then
    ok "pip"
else
    fail "pip"
fi

echo
echo "--- Source tools ---"

[ -d "$PARAMSPIDER_DIR" ] && ok "ParamSpider source" || warn "ParamSpider source"
[ -d "$CMSMAP_DIR" ] && ok "CMSmap source" || warn "CMSmap source"
[ -d "$LINKFINDER_DIR" ] && ok "LinkFinder source" || warn "LinkFinder source"
[ -d "$TPLMAP_DIR" ] && ok "Tplmap source" || warn "Tplmap source"
[ -d "$CLOUDENUM_DIR" ] && ok "cloud_enum source" || warn "cloud_enum source"
[ -d "$GRAPHW00F_DIR" ] && ok "graphw00f source" || warn "graphw00f source"
[ -d "$JWT_DIR" ] && ok "jwt_tool source" || warn "jwt_tool source"

echo
echo "--- Resources ---"

[ -x "$TESTSSL_DIR/testssl.sh" ] \
    && ok "testssl.sh" \
    || warn "testssl.sh"

[ -f "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt" ] || \
[ -d "/usr/share/seclists/Discovery/DNS" ] \
    && ok "SecLists" \
    || warn "SecLists"

[ -f "$PROJECT_DIR/config/resolvers.txt" ] \
    && ok "config/resolvers.txt" \
    || warn "config/resolvers.txt"

[ -f "$HOME/.subjack/fingerprints.json" ] \
    && ok "subjack fingerprints" \
    || warn "subjack fingerprints"

if [ -d "$NUCLEI_DIR" ]; then
    TEMPLATE_COUNT="$(find "$NUCLEI_DIR" -type f -name '*.yaml' 2>/dev/null | wc -l)"
    echo "[INFO] Nuclei YAML templates: $TEMPLATE_COUNT"
else
    warn "Nuclei template directory"
fi

echo
echo "============================================================"
echo "INSTALLATION SUMMARY"
echo "============================================================"

if [ "${#FAILED[@]}" -eq 0 ]; then
    echo
    echo "ALL INSTALLATION STEPS COMPLETED."
    echo
    echo "Activate the environment:"
    echo "  source $VENV/bin/activate"
    echo
    echo "Go binaries:"
    echo "  $GO_BIN"
    echo
    exit 0
else
    echo
    echo "Some installation steps failed:"
    printf '  - %s\n' "${FAILED[@]}"
    echo
    echo "The installer continued so you can see every failure."
    echo
    exit 1
fi
