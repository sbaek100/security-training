#!/bin/bash
# Check target URL
if [ $# -eq 0 ]; then
echo "Usage: $0 <target_URL> [depth]"
echo "Example: $0 http://192.168.0.100 2"
exit 1
fi
# Variable setup
TARGET_URL="$1"
MAX_DEPTH="${2:-1}" # Default depth 1
OUTPUT_FILE="web_structure_$(echo $TARGET_URL | sed 's/[^a-zA-Z0-9]/_/g').txt"
echo "Target URL: $TARGET_URL"
echo "Maximum depth: $MAX_DEPTH"
echo "Output file: $OUTPUT_FILE"
echo
# Create initial directory structure file
echo "Web directory structure: $TARGET_URL" > "$OUTPUT_FILE"
echo "Scan date: $(date)" >> "$OUTPUT_FILE"
echo "==============================================" >> "$OUTPUT_FILE"
# Crawl web structure using wget
echo "Crawling web structure..."
wget --spider --force-html -r -l "$MAX_DEPTH" "$TARGET_URL" 2>&1 | \
grep '^--' | awk '{ print $3 }' | \
grep -v '\.\(css\|js\|png\|jpg\|jpeg\|gif\|pdf\|xml\|txt\)$' | \
sort | uniq >> "$OUTPUT_FILE"
echo "Web directory structure analysis complete. Results saved to $OUTPUT_FILE file."
# Basic information for discovered directories (optional)
echo
echo "Major directories discovered:"
grep -i "/$" "$OUTPUT_FILE" | head -10
# Web application identification attempt
echo
echo "Possible web application identification:"
if grep -q "/dvwa/" "$OUTPUT_FILE"; then
echo "[+] DVWA (Damn Vulnerable Web Application) found"
fi
if grep -q "/mutillidae/" "$OUTPUT_FILE"; then
echo "[+] Mutillidae found"
fi
if grep -q "/phpmyadmin/" "$OUTPUT_FILE"; then
echo "[+] phpMyAdmin found"
fi
if grep -q "/tikiwiki/" "$OUTPUT_FILE"; then
echo "[+] TikiWiki found"
fi
