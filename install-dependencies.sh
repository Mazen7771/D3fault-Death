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
        if git -C "$dir" fetch --depth 1 origin; then
            git -C "$dir" reset --hard origin/HEAD 2>/dev/null || true
            ok "$description (updated)"
        else
            warn "$description fetch failed; using existing checkout"
        fi
        return 0
    fi

    if git clone --depth 1 "$url" "$dir"; then
        ok "$description"
    else
        fail "$description"
        return 1
    fi
}

go_install() {
    local module="$1"
    local binary

    binary="$(basename "${module%@*}")"

    echo "[+] go install $module"

    if GOBIN="$GO_BIN" go install "$module"; then
        ok "$binary"
    else
        fail "Go: $module"
    fi
}

section "[1/9] SYSTEM / BOOTSTRAP"

if sudo apt-get update; then
    ok "apt update"
else
    fail "apt update"
fi

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

    # Correct current unew repository
    "github.com/dwisiswant0/unew@latest"

    "github.com/lc/gau/v2/cmd/gau@latest"

    "github.com/ffuf/ffuf/v2@latest"
    "github.com/OJ/gobuster/v3@latest"

    "github.com/trufflesecurity/trufflehog/v3@latest"
    "github.com/zricethezav/gitleaks/v8@latest"

    "github.com/sensepost/gowitness@latest"
    "github.com/hahwul/dalfox/v2@latest"

    "github.com/haccer/subjack@latest"

    # Correct current subzy repository
    "github.com/PentestPad/subzy@latest"

    # Correct current kiterunner repository
    "github.com/assetnote/kiterunner/cmd/kr@latest"

    "github.com/anchore/grype/cmd/grype@latest"
    "github.com/anchore/syft/cmd/syft@latest"

    "github.com/BishopFox/jsluice/cmd/jsluice@latest"
    "github.com/brosck/mantra@latest"
)

for module in "${GO_TOOLS[@]}"; do
    go_install "$module"
done

section "[4/9] PYTHON VIRTUAL ENVIRONMENT"

if [ ! -d "$VENV" ]; then
    if python3 -m venv "$VENV"; then
        ok "Create Python virtual environment"
    else
        fail "Create Python virtual environment"
    fi
else
    ok "Python virtual environment already exists"
fi

if [ -x "$VENV/bin/activate" ]; then
    source "$VENV/bin/activate"
else
    fail "Python virtual environment activation script"
fi

if "$VENV/bin/python" -m pip install --upgrade pip setuptools wheel; then
    ok "Upgrade pip/setuptools/wheel"
else
    fail "Upgrade pip/setuptools/wheel"
fi

if [ -f "$PROJECT_DIR/requirements.txt" ]; then
    pip_install "Install requirements.txt" \
        -r "$PROJECT_DIR/requirements.txt"
else
    warn "requirements.txt not found"
fi

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

# Tplmap is legacy Python code.
# Its upstream requirements contain obsolete packages and should not
# be installed blindly into the modern project virtual environment.
#
# We only prepare the source here so that this legacy tool does not
# break the rest of the installer.

if [ -d "$TPLMAP_DIR" ]; then
    ok "Tplmap source prepared (legacy dependency setup skipped)"
fi

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

    if [ -d "$TOOLS_DIR/ghauri" ]; then
        pip_install "Install ghauri from source" \
            "$TOOLS_DIR/ghauri"
    fi
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

        if sudo cp -a "$TOOLS_DIR/SecLists/." /usr/share/seclists/; then
            ok "SecLists copied to /usr/share/seclists"
        else
            fail "SecLists copy to /usr/share/seclists"
        fi
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

# No external fingerprints.json download.
# Current Subjack releases embed fingerprints directly into the binary.

ok "Subjack fingerprints embedded in binary"

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

if [ -d "$RACETHEWEB_DIR" ]; then

    if (
        cd "$RACETHEWEB_DIR" &&
        make build
    ); then

        RTW_BINARY=""

        while IFS= read -r candidate; do
            if [ -z "$RTW_BINARY" ]; then
                RTW_BINARY="$candidate"
            fi
        done < <(
            find "$RACETHEWEB_DIR" \
                -maxdepth 1 \
                -type f \
                -name 'race-the-web*' \
                -perm -111 \
                2>/dev/null
        )

        if [ -n "$RTW_BINARY" ] && [ -f "$RTW_BINARY" ]; then
            cp "$RTW_BINARY" "$GO_BIN/race-the-web"
            chmod +x "$GO_BIN/race-the-web"
            ok "Race-the-Web binary"
        else
            fail "Race-the-Web binary"
        fi

    else
        fail "Race-the-Web build"
    fi

else
    fail "Race-the-Web source missing"
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

[ -d "$PARAMSPIDER_DIR" ] \
    && ok "ParamSpider source" \
    || warn "ParamSpider source"

[ -d "$CMSMAP_DIR" ] \
    && ok "CMSmap source" \
    || warn "CMSmap source"

[ -d "$LINKFINDER_DIR" ] \
    && ok "LinkFinder source" \
    || warn "LinkFinder source"

[ -d "$TPLMAP_DIR" ] \
    && ok "Tplmap source" \
    || warn "Tplmap source"

[ -d "$CLOUDENUM_DIR" ] \
    && ok "cloud_enum source" \
    || warn "cloud_enum source"

[ -d "$GRAPHW00F_DIR" ] \
    && ok "graphw00f source" \
    || warn "graphw00f source"

[ -d "$JWT_DIR" ] \
    && ok "jwt_tool source" \
    || warn "jwt_tool source"

echo
echo "--- Resources ---"

[ -x "$TESTSSL_DIR/testssl.sh" ] \
    && ok "testssl.sh" \
    || warn "testssl.sh"

if [ -f "/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt" ] || \
   [ -d "/usr/share/seclists/Discovery/DNS" ]; then
    ok "SecLists"
else
    warn "SecLists"
fi

[ -f "$PROJECT_DIR/config/resolvers.txt" ] \
    && ok "config/resolvers.txt" \
    || warn "config/resolvers.txt"

ok "subjack fingerprints embedded in binary"

if [ -d "$NUCLEI_DIR" ]; then
    TEMPLATE_COUNT="$(
        find "$NUCLEI_DIR" \
            -type f \
            -name '*.yaml' \
            2>/dev/null | wc -l
    )

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
