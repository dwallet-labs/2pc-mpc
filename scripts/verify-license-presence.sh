#!/bin/bash

# Predefined SHA-256 hash of the expected LICENSE file content
expected_hash="249cc4deb5f6252f56d7df28a58e5c6387140fc7b7da0360088853335cc2583b"

# Check if the LICENSE file exists in the current directory
if [ -f "./LICENSE" ]; then
    # Determine the correct command for SHA-256 hashing based on the available command
    if command -v sha256sum >/dev/null 2>&1; then
        hash_command="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        hash_command="shasum -a 256"
    else
        echo "Error: No suitable hashing command found (sha256sum or shasum)."
        exit 1
    fi

    # Compute the SHA-256 hash of the LICENSE file's content
    actual_hash=$($hash_command "./LICENSE" | awk '{ print $1 }')

    # Compare the computed hash with the expected hash
    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "The LICENSE file's content does NOT match the expected content."
        exit 1
    fi
else
    echo "LICENSE file not found."
    exit 1
fi