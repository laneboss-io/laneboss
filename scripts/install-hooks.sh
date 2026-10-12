#!/bin/sh
# Install a pre-commit hook that runs scripts/scan.sh --staged and blocks a commit that fails it.
# With --denylist FILE the hook always applies that denylist; LANEBOSS_SCAN_DENYLIST still overrides it.
set -eu
usage="usage: install-hooks.sh [--denylist FILE]"
denylist=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --denylist)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "install-hooks: --denylist needs a file; $usage" >&2
                exit 2
            fi
            denylist=$2
            shift 2
            ;;
        -h|--help)
            echo "$usage"
            exit 0
            ;;
        *)
            echo "install-hooks: unknown argument; $usage" >&2
            exit 2
            ;;
    esac
done
if ! top=$(git rev-parse --show-toplevel 2>/dev/null); then
    echo "install-hooks: run this inside a Git work tree" >&2
    exit 2
fi
if [ ! -f "$top/scripts/scan.sh" ]; then
    echo "install-hooks: $top/scripts/scan.sh does not exist" >&2
    exit 2
fi
if [ -n "$denylist" ]; then
    case "$denylist" in
        /*) ;;
        *) denylist=$(pwd -P)/$denylist ;;
    esac
    if [ ! -r "$denylist" ]; then
        echo "install-hooks: cannot read the denylist file" >&2
        exit 2
    fi
fi
hooks=$(git rev-parse --git-path hooks)
case "$hooks" in
    /*) ;;
    *) hooks=$(pwd -P)/$hooks ;;
esac
mkdir -p "$hooks"
hook=$hooks/pre-commit
marker="# installed by scripts/install-hooks.sh"
if [ -e "$hook" ] && ! grep -q "^$marker\$" "$hook"; then
    echo "install-hooks: $hook exists and was not written by this script; merge it by hand" >&2
    exit 2
fi
temporary=$hook.$$.tmp
{
    echo "#!/bin/sh"
    echo "$marker"
    echo "# Blocks a commit whose staged content fails the publication scan."
    if [ -n "$denylist" ]; then
        quoted=$(printf '%s' "$denylist" | sed "s/'/'\\\\''/g")
        echo "LANEBOSS_SCAN_DENYLIST=\${LANEBOSS_SCAN_DENYLIST:-'$quoted'}"
        echo "export LANEBOSS_SCAN_DENYLIST"
    fi
    echo 'top=$(git rev-parse --show-toplevel) || exit 1'
    echo 'exec sh "$top/scripts/scan.sh" --staged "$top"'
} > "$temporary"
chmod 755 "$temporary"
mv "$temporary" "$hook"
echo "installed $hook"
