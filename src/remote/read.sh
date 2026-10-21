set -eu
config="$HOME/.ssh/config"
if [ -e "$config" ]; then
    [ -f "$config" ] || { echo 'SSH config is not a regular file' >&2; exit 1; }
    [ "$(wc -c < "$config")" -le 2097152 ] || { echo 'SSH config exceeds 2 MiB' >&2; exit 1; }
    printf '1\n'
    cat "$config"
else
    [ ! -L "$config" ] || { echo 'SSH config is a dangling symlink' >&2; exit 1; }
    printf '0\n'
fi
