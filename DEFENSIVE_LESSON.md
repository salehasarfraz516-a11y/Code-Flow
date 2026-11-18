# Defensive Lesson: Parameterized SQL Queries

Parameterized queries keep SQL code separate from data. A database driver
places placeholders in the SQL statement and binds values separately:

```python
cursor.execute(
    "SELECT * FROM users WHERE name = ?",
    (name,),
)
```

This matters because the database treats the bound value as data, not executable
SQL syntax. It prevents attacker-controlled input from changing the query's
structure and also makes intent explicit for reviewers.

The placeholder syntax varies by driver. SQLite uses `?`, while PostgreSQL
often uses `%s`. Always use the placeholder style supported by the installed
driver; never escape SQL strings by hand or concatenate user input into SQL.
