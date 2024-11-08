# Test data

The `generator` folder contains a script, `generate.py`, which writes 500,000 records to a parquet file. To run the sample queries in [docs/tables](../tables), cd into `generator` and run:

```bash
$ python generate.py
Generating normal records...
Generating suspicious records...
Converting to DataFrame...
Saving to parquet...
Generated 500000 records in 10.64 seconds
```

The output is `github_audit_log.parquet`.

In `generator`, run DuckDB.

```bash
$ duckdb
v1.1.3 19864453f7
Enter ".help" for usage hints.
Connected to a transient in-memory database.
Use ".open FILENAME" to reopen on a persistent database.
D CREATE VIEW github_audit_log AS SELECT * FROM read_parquet('github_audit_log.parquet');
```

You can copy queries from the table docs and paste them here.

```sql
select
    actor,
    count(*) as branch_deletions
  from
    github_audit_log
  where
    action = 'protected_branch.destroy'
  group by
    actor
  having
    branch_deletions > 3;
```

```
┌────────────┬──────────────────┐
│   actor    │ branch_deletions │
│  varchar   │      int64       │
├────────────┼──────────────────┤
│ dependabot │              148 │
│ janesmith  │              132 │
│ bobwilson  │              132 │
│ renovate   │              148 │
│ johndoe    │              147 │
└────────────┴──────────────────┘
```


