#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

sha256sum -c THIRD_PARTY_ASSETS.sha256
find . -path './build' -prune -o -name '*.php' -exec php -l {} \;
node test/test_recovery_protocol.js
python3 test/test_recovery_protocol.py
bash -n build.sh run-security-utils.sh install-native.sh flatpak-wrapper.sh snap/security-utils-wrapper

if rg -n '<(script|link)[^>]+(src|href)="https?://' --glob '*.php' --glob '*.html'; then
    echo 'External runtime asset found' >&2
    exit 1
fi

if rg -n 'seccomp:unconfined|--filesystem=host|Math\.random|mousemove' \
    --glob '!security_utils_developer_recommendations.md' --glob '!RELEASE_NOTES.md' \
    --glob '!test/**' --glob '!js/vendor/**' --glob '!css/vendor/**'; then
    echo 'Forbidden security regression found' >&2
    exit 1
fi

if command -v docker >/dev/null 2>&1; then
    docker compose config >/dev/null
fi

if rg -n 'uses: [^ ]+@(v[0-9]+|main|master)$' .github/workflows; then
    echo 'GitHub Action is not pinned to an immutable commit' >&2
    exit 1
fi

echo 'Security checks passed'
