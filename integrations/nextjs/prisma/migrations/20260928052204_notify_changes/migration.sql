-- live updates (@rowstile/react): NOTIFY authz_changes whenever access may have changed
INSERT INTO authz.settings VALUES ('notify_changes', 'on') ON CONFLICT (key) DO UPDATE SET value = 'on';
