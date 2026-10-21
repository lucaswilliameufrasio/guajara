set -eu
umask 077
directory="$HOME/.ssh"
mkdir -p "$directory"
lock="$directory/.guajara-config.lock"
mkdir "$lock" 2>/dev/null || { echo 'SSH config is locked by another Guajara operation' >&2; exit 1; }
temporary=''
cleanup() {
    if [ -n "$temporary" ]; then
        rm -f "$temporary/expected" "$temporary/new"
        rmdir "$temporary"
    fi
    rmdir "$lock"
}
trap cleanup 0
trap 'exit 1' 1 2 15
temporary=$(mktemp -d "$directory/.guajara.XXXXXX")
IFS=' ' read -r expected_exists expected_length new_length
case "$expected_exists" in 0|1) ;; *) echo 'Invalid snapshot flag' >&2; exit 1;; esac
case "$expected_length:$new_length" in *[!0-9:]*|:*|*:) echo 'Invalid frame length' >&2; exit 1;; esac
[ "$expected_length" -le 2097152 ] && [ "$new_length" -le 2097152 ] || { echo 'SSH config exceeds 2 MiB' >&2; exit 1; }
dd bs=1 count="$expected_length" of="$temporary/expected" 2>/dev/null
dd bs=1 count="$new_length" of="$temporary/new" 2>/dev/null
[ "$(wc -c < "$temporary/expected")" -eq "$expected_length" ] && [ "$(wc -c < "$temporary/new")" -eq "$new_length" ] || { echo 'Incomplete config transfer; nothing saved' >&2; exit 1; }
config="$directory/config"
[ ! -L "$config" ] || { echo 'Refusing to replace a symlink SSH config' >&2; exit 1; }
if [ "$expected_exists" -eq 1 ]; then
    [ -f "$config" ] && cmp -s "$temporary/expected" "$config" || { echo 'SSH config changed; reload before saving' >&2; exit 1; }
else
    [ ! -e "$config" ] || { echo 'SSH config appeared; reload before saving' >&2; exit 1; }
fi
chmod 600 "$temporary/new"
mv -f "$temporary/new" "$config"
printf 'GUAJARA_SAVED\n'
