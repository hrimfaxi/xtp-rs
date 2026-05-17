#!/bin/bash

# Find all .rs files, skipping any 'target' directory (and its contents)
find . -type d -name "target" -prune -o -type f -name "*.rs" -exec sh -c '
    echo "=== FILE: $1 ==="
    cat "$1"
    echo
' _ {} \;
