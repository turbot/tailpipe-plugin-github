#!/bin/bash

# Define file paths
QUERY_FILE="/Users/vedmisra/turbot/tailpipe-plugin-github/docs/tables/github_audit_log.md"           # The markdown file containing the queries
TEST_RESULT_FILE="/Users/vedmisra/turbot/tailpipe-plugin-github/test_results.txt"  # The file to log pass/fail results
PARQUET_FILE="github_audit_log.parquet"


# Create a new DuckDB instance
DB_FILE="temp_duckdb.db"

# Initialize the test results file
echo "Test Results" > "$TEST_RESULT_FILE"
echo "---------------------" >> "$TEST_RESULT_FILE"

# Create a view in DuckDB for the parquet file
duckdb "$DB_FILE" "CREATE VIEW github_audit_log AS SELECT * FROM read_parquet('$PARQUET_FILE');" >/dev/null 2>&1

# Read each line of the .md file
QUERY=""
IN_SQL_BLOCK=false

while IFS= read -r line; do
    # Detect the start of SQL code block
    if [[ "$line" == "\`\`\`sql" ]]; then
        IN_SQL_BLOCK=true
        QUERY=""  # Reset query
        continue
    fi

    # Detect the end of SQL code block
    if [[ "$line" == "\`\`\`" ]]; then
        IN_SQL_BLOCK=false
        
        # Execute the query if it is not empty
        if [[ -n $QUERY ]]; then
            duckdb "$DB_FILE" "$QUERY" >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                echo "Query Passed: $QUERY" >> "$TEST_RESULT_FILE"
            else
                echo "Query Failed: $QUERY" >> "$TEST_RESULT_FILE"
            fi
        fi
        continue
    fi

    # Accumulate lines as part of the SQL query if within a SQL block
    if [[ "$IN_SQL_BLOCK" == true ]]; then
        QUERY+="$line "
    fi
done < "$QUERY_FILE"

# Clean up temporary DuckDB instance
rm "$DB_FILE"

echo "Test completed. Results are in $TEST_RESULT_FILE"