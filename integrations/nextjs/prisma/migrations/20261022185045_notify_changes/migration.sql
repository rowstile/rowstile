-- live updates (@rowstile/react): NOTIFY authz_changes whenever access may have changed. After the policy's
-- migration, which makes authz.settings
INSERT INTO authz.settings VALUES ('notify_changes', 'on') ON CONFLICT (key) DO UPDATE SET value = 'on';
