#!/bin/bash

# Array to hold the names of files that do not match the expected starting lines
non_conforming_files=()

# Expected lines
expected_line1="// Author: dWallet Labs, Ltd."
expected_line2="// SPDX-License-Identifier: BSD-3-Clause-Clear"

# Recursively find all .rs files and check their first two lines
while IFS= read -r file; do
    # Use wc -l to count the number of lines in the file
    line_count=$(wc -l < "$file")

    # Check if the file has at least two lines
    if [ "$line_count" -lt 2 ]; then
        non_conforming_files+=("$file")
        continue # Skip to the next file
    fi

    # Read the first and second lines
    line1=$(head -n 1 "$file")
    line2=$(head -n 2 "$file" | tail -n 1)

    # Initialize a flag to indicate if the file does not conform
    file_does_not_conform=false

    # Compare the first line
    if [[ "$line1" != "$expected_line1" ]]; then
        file_does_not_conform=true
    fi

    # Compare the second line
    if [[ "$line2" != "$expected_line2" ]]; then
        file_does_not_conform=true
    fi

    # If the file does not conform, add it to the list
    if [ "$file_does_not_conform" = true ]; then
        non_conforming_files+=("$file")
    fi
done < <(find . -type f -name '*.rs')

# Check if there are any non-conforming files
if [ ${#non_conforming_files[@]} -ne 0 ]; then
    echo "The following files have file-license-prefix issues (either do not start with the expected license-lines or do not have at least two lines):"
    printf '%s\n' "${non_conforming_files[@]}"
    exit 1
fi
