#!/bin/sh
# Install Bulwark so it can be run as `bulwark` instead of a long path.
#
#   sudo ./install.sh
#
# Puts the tree in /opt/bulwark, a small wrapper on PATH, and a config file
# holding the options you would otherwise type on every run. Override any of
# it with environment variables:
#
#   INSTALL_DIR=/usr/local/lib/bulwark BIN_DIR=/usr/bin sudo -E ./install.sh
#   EVIDENCE_DIR=/var/lib/ir sudo -E ./install.sh
#
# Works with whichever form of Bulwark is sitting next to this script:
#
#   bulwark-standalone.py        the single readable source file
#   bulwark.pyz                  the single compact executable
#   bulwark.py + bulwark/        the package directory
#
# Drop this script beside any one of them and run it. If more than one is
# present the single-file forms win, because that is what someone who copied
# one file onto a box is asking for.
#
# POSIX sh on purpose: this has to work on a minimal image where bash may not
# be the shell. It copies files and writes two of its own; it does not touch
# any system configuration beyond its own config file.

set -eu

INSTALL_DIR="${INSTALL_DIR:-/opt/bulwark}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
CONFIG_FILE="${CONFIG_FILE:-/etc/bulwark.conf}"
EVIDENCE_DIR="${EVIDENCE_DIR:-/root/bulwark}"
PYTHON="${PYTHON:-python3}"

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- checks

[ "$(id -u)" = "0" ] || die "run with sudo: writing to $INSTALL_DIR and $BIN_DIR needs root"

# Work out which form of Bulwark sits next to this script. LAYOUT is one of
# "package", "standalone" or "pyz"; ENTRY is the file the wrapper will run.
#
# A single .py file is identified by its contents, not its name. People rename
# the single-file build to bulwark.py, which otherwise looks exactly like the
# package's thin entry script - and that script is useless without the
# bulwark/ directory beside it. The distinguishing feature is the import: the
# entry script does `from bulwark.cli import main`, while the flattened build
# imports nothing from the package because it already contains all of it.
is_self_contained() {
    [ -f "$1" ] || return 1
    ! grep -Eq '^[[:space:]]*(from|import)[[:space:]]+bulwark([.[:space:]]|$)' "$1"
}

LAYOUT=""
if [ -f "$SOURCE_DIR/bulwark.py" ] && [ -d "$SOURCE_DIR/bulwark" ]; then
    # The package wins when both are present: in a repo checkout the
    # single-file builds are generated artifacts, and installing a stale one
    # instead of the source it came from would be a trap.
    LAYOUT="package"
    ENTRY="bulwark.py"
else
    # Any lone .py that carries the whole tool, whatever it is called.
    for candidate in bulwark-standalone.py bulwark.py bulwark-single.py; do
        if is_self_contained "$SOURCE_DIR/$candidate"; then
            LAYOUT="standalone"
            ENTRY="$candidate"
            break
        fi
    done
fi

if [ -z "$LAYOUT" ] && [ -f "$SOURCE_DIR/bulwark.pyz" ]; then
    LAYOUT="pyz"
    ENTRY="bulwark.pyz"
fi

if [ -z "$LAYOUT" ]; then
    if [ -f "$SOURCE_DIR/bulwark.py" ]; then
        die "bulwark.py here is the package's entry script: it needs the
bulwark/ directory beside it, which is missing. Either copy that directory
across too, or use a single-file build (bulwark-standalone.py or bulwark.pyz)."
    fi
    die "no Bulwark found next to this script ($SOURCE_DIR).
Put one of these beside install.sh:
  bulwark-standalone.py    the whole tool in one readable file
                           (also accepted as bulwark.py, when that file is
                           the single-file build rather than the package's
                           entry script)
  bulwark.pyz              the whole tool in one compact executable
  bulwark.py and bulwark/  the package directory"
fi

command -v "$PYTHON" >/dev/null 2>&1 \
    || die "$PYTHON not found. Bulwark needs Python 3.8 or newer; set PYTHON=/path/to/python3 if it is installed elsewhere."

"$PYTHON" - <<'PYEOF' || die "$PYTHON is too old. Bulwark needs Python 3.8 or newer."
import sys
raise SystemExit(0 if sys.version_info >= (3, 8) else 1)
PYEOF

case "$(uname -s)" in
    Linux) ;;
    *) say "warning: this is $(uname -s), not Linux. Bulwark reads /proc and" \
            "distribution paths that may not exist here." ;;
esac

# ---------------------------------------------------------------- install

say "Installing Bulwark"
say "  from    $SOURCE_DIR"
say "  to      $INSTALL_DIR"

if [ -d "$INSTALL_DIR" ]; then
    say "  (replacing the existing install; evidence and config are left alone)"
    rm -rf "$INSTALL_DIR.old"
    mv "$INSTALL_DIR" "$INSTALL_DIR.old"
fi

mkdir -p "$INSTALL_DIR"

# A single-file build is one file. The package is an entry script plus the
# bulwark/ directory beside it. Both end up behind the same wrapper, so
# nothing downstream needs to know which was installed.
case "$LAYOUT" in
    package)
        cp "$SOURCE_DIR/bulwark.py" "$INSTALL_DIR/"
        cp -r "$SOURCE_DIR/bulwark" "$INSTALL_DIR/"
        say "  form    package (entry script plus bulwark/ directory)"
        ;;
    standalone)
        cp "$SOURCE_DIR/$ENTRY" "$INSTALL_DIR/"
        say "  form    single readable source file"
        ;;
    pyz)
        cp "$SOURCE_DIR/$ENTRY" "$INSTALL_DIR/"
        say "  form    single executable archive"
        ;;
esac

# Compiled caches from another machine or another Python are not wanted here.
find "$INSTALL_DIR" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

chown -R root:root "$INSTALL_DIR" 2>/dev/null || true
chmod -R go-w "$INSTALL_DIR"
chmod 0755 "$INSTALL_DIR/$ENTRY"

# ---------------------------------------------------------------- wrapper

mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/bulwark" <<EOF
#!/bin/sh
# Bulwark launcher, written by install.sh
exec "$PYTHON" "$INSTALL_DIR/$ENTRY" "\$@"
EOF
chmod 0755 "$BIN_DIR/bulwark"
chown root:root "$BIN_DIR/bulwark" 2>/dev/null || true
say "  wrapper $BIN_DIR/bulwark"

# ----------------------------------------------------------------- config

if [ -f "$CONFIG_FILE" ]; then
    say "  config  $CONFIG_FILE (already present, left unchanged)"
else
    cat > "$CONFIG_FILE" <<EOF
# Bulwark configuration, created by install.sh
#
# These values are used when the matching command-line option is not given,
# so you do not have to type -o and a baseline path on every run. Environment
# variables (BULWARK_OUTPUT_DIR and friends) win over this file, and a
# command-line flag wins over both. Run \`bulwark status\` to see what is in
# effect and where each value came from.
#
# Keep this file root-owned and not writable by anyone else: Bulwark ignores a
# config file other users can write, because it controls where evidence goes.

# Where assessment evidence directories are written.
output_dir = $EVIDENCE_DIR

# Default baseline for \`bulwark snap\` and \`bulwark check\`.
baseline = $EVIDENCE_DIR/baseline.json

# How far back to read logs and look for recent changes, in hours.
lookback_hours = 72

# How many findings the terminal summary shows.
top = 10
EOF
    chmod 0644 "$CONFIG_FILE"
    chown root:root "$CONFIG_FILE" 2>/dev/null || true
    say "  config  $CONFIG_FILE"
fi

mkdir -p "$EVIDENCE_DIR"
chmod 0700 "$EVIDENCE_DIR"
say "  evidence $EVIDENCE_DIR"

# ------------------------------------------------------------------ check

if ! "$BIN_DIR/bulwark" --version >/dev/null 2>&1; then
    die "installed, but '$BIN_DIR/bulwark --version' failed. Check $INSTALL_DIR."
fi

say ""
say "Installed: $("$BIN_DIR/bulwark" --version)"

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) say ""
       say "note: $BIN_DIR is not on your PATH. Either add it, or call"
       say "      $BIN_DIR/bulwark directly." ;;
esac

say ""
say "Start here:"
say "  sudo bulwark quick      fast triage"
say "  sudo bulwark audit      full assessment"
say "  sudo bulwark snap       record the state you have accepted"
say "  sudo bulwark check      what changed since then (re-run through the round)"
say ""
say "Reports land in $EVIDENCE_DIR. Copy them off the host before you change anything."
