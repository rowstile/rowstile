-- kept_columns.sql: every table of schema app gets a column of each name in :names (one a line), NULL in every row;
-- a column a table has already stays as it is. tests/hand_answers.sh --kept-names runs it, with the names the
-- policy's generated functions keep for themselves.
SELECT format('ALTER TABLE %s %s', c.oid::regclass, string_agg(format('ADD COLUMN IF NOT EXISTS %I text', n), ', '))
  FROM pg_class c, regexp_split_to_table(:'names', E'\n') n
 WHERE c.relnamespace = 'app'::regnamespace AND c.relkind = 'r'
 GROUP BY c.oid \gexec
