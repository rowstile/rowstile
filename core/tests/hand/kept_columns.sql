-- kept_columns.sql: every table of schema app gets a column of each name in :names (one a line), NULL in every row;
-- a column a table has already stays as it is. tests/hand_answers.sh --kept-names runs it, with the names the
-- policy's generated SQL keeps for itself and every word it writes by itself (tests/kept_names.py). Not the words
-- Postgres keeps for itself (reserved: a column of that name is written in quotes, and the bare word is never one).
SELECT format('ALTER TABLE %s %s', c.oid::regclass, string_agg(format('ADD COLUMN IF NOT EXISTS %I text', n), ', '))
  FROM pg_class c, regexp_split_to_table(:'names', E'\n') n
 WHERE c.relnamespace = 'app'::regnamespace AND c.relkind = 'r'
   AND n NOT IN (SELECT word FROM pg_catalog.pg_get_keywords() WHERE catcode IN ('R', 'T'))
 GROUP BY c.oid \gexec
