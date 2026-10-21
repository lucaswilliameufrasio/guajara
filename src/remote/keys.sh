set -eu
for key in "$HOME"/.ssh/*; do
    [ -f "$key" ] || continue
    [ ! -L "$key" ] || continue
    header=$(LC_ALL=C head -c 40 "$key" 2>/dev/null) || continue
    case "$header" in
        '-----BEGIN OPENSSH PRIVATE KEY-----'*|'-----BEGIN RSA PRIVATE KEY-----'*|'-----BEGIN EC PRIVATE KEY-----'*|'-----BEGIN DSA PRIVATE KEY-----'*|'-----BEGIN PRIVATE KEY-----'*|'-----BEGIN ENCRYPTED PRIVATE KEY-----'*)
            printf '%s\000' "$key"
            ;;
    esac
done
