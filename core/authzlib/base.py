"""SQL kept across re-applies: the tables people's data lives in, and migrations."""

BASE_SQL = r"""-- Base objects (kept across re-applies)
CREATE SCHEMA IF NOT EXISTS authz;
REVOKE ALL ON SCHEMA authz FROM PUBLIC;

-- Shares people create in the app, for relations marked 'shared' (and custom role assignments)
CREATE TABLE IF NOT EXISTS authz.shares (
  object_type      text        NOT NULL,
  object_id        text        NOT NULL,
  relation         text        NOT NULL,
  subject_type     text        NOT NULL,
  subject_id       text        NOT NULL,
  subject_relation text        NOT NULL DEFAULT '',
  expires_at       timestamptz,
  created_by       text,
  starts_at        timestamptz,
  caveat           text,
  caveat_args      jsonb,
  created_at       timestamptz DEFAULT now(),
  PRIMARY KEY (object_type, object_id, relation, subject_type, subject_id, subject_relation));
CREATE INDEX IF NOT EXISTS shares_by_subject
  ON authz.shares (subject_type, subject_id, subject_relation, object_type, relation);
REVOKE ALL ON authz.shares FROM PUBLIC;

-- Custom roles: sets of permissions defined as data, assigned like shares ('role:<id>')
CREATE TABLE IF NOT EXISTS authz.roles (
  id          bigserial PRIMARY KEY,
  owner_type  text NOT NULL,
  owner_id    text NOT NULL,
  object_type text NOT NULL,
  name        text NOT NULL,
  created_by  text,
  created_at  timestamptz DEFAULT now(),
  UNIQUE (owner_type, owner_id, object_type, name));
CREATE TABLE IF NOT EXISTS authz.role_permissions (
  role_id    bigint NOT NULL REFERENCES authz.roles ON DELETE CASCADE,
  permission text   NOT NULL,
  PRIMARY KEY (role_id, permission));
REVOKE ALL ON authz.roles, authz.role_permissions FROM PUBLIC;

-- API keys (only a hash of each is kept)
CREATE TABLE IF NOT EXISTS authz.api_keys (
  id           bigserial PRIMARY KEY,
  user_id      text NOT NULL,
  name         text NOT NULL,
  prefix       text NOT NULL,
  hash         text NOT NULL UNIQUE,
  scopes       text NOT NULL DEFAULT '',
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz,
  last_used_at timestamptz,
  revoked_at   timestamptz,
  -- whose key: user_id is the principal's id, of this type
  principal_type text NOT NULL DEFAULT 'user');
-- Settings for the functions (jwt_secret, jwt_issuer, jwt_audience, jwt_user_claim, jwt_type_claim, ...)
CREATE TABLE IF NOT EXISTS authz.settings (key text PRIMARY KEY, value text NOT NULL);
-- The audit trail: every share, role, key, request and impersonation, and relationship changes
CREATE TABLE IF NOT EXISTS authz.audit (
  id               bigserial PRIMARY KEY,
  at               timestamptz NOT NULL DEFAULT clock_timestamp(),
  txid             bigint NOT NULL DEFAULT txid_current(),
  db_role          text,
  user_id          text,
  acting_user      text,
  action           text NOT NULL,
  object_type      text,
  object_id        text,
  relation         text,
  subject_type     text,
  subject_id       text,
  subject_relation text,
  detail           jsonb,
  reason           text);
CREATE INDEX IF NOT EXISTS audit_by_object ON authz.audit (object_type, object_id, at);
REVOKE ALL ON authz.api_keys, authz.settings, authz.audit FROM PUBLIC;

-- Change feed: objects whose access may have changed, for caches, search indexes, file stores
CREATE TABLE IF NOT EXISTS authz.changes (
  pos         bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT clock_timestamp(),
  txid        bigint NOT NULL DEFAULT txid_current(),
  object_type text NOT NULL,
  object_ids  text[] NOT NULL,
  cause       text NOT NULL);
-- Access requests, approvals, and emergency access
CREATE TABLE IF NOT EXISTS authz.requests (
  id          bigserial PRIMARY KEY,
  object_type text NOT NULL,
  object_id   text NOT NULL,
  relation    text NOT NULL,
  requester   text NOT NULL,
  reason      text,
  duration    interval,
  status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'cancelled')),
  decided_by  text,
  decided_at  timestamptz,
  note        text,
  created_at  timestamptz NOT NULL DEFAULT now());
-- Access reviews: a snapshot of the shares on an object, each kept or revoked by a reviewer
CREATE TABLE IF NOT EXISTS authz.reviews (
  id          bigserial PRIMARY KEY,
  object_type text NOT NULL,
  object_id   text NOT NULL,
  created_by  text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  closes_at   timestamptz,
  closed_at   timestamptz);
CREATE TABLE IF NOT EXISTS authz.review_items (
  review_id        bigint NOT NULL REFERENCES authz.reviews ON DELETE CASCADE,
  item             int    NOT NULL,
  relation         text   NOT NULL,
  subject_type     text   NOT NULL,
  subject_id       text   NOT NULL,
  subject_relation text   NOT NULL,
  expires_at       timestamptz,
  keep             boolean,
  decided_by       text,
  decided_at       timestamptz,
  PRIMARY KEY (review_id, item));
-- The SELECT that masks took away from a role, to give back when they go: the table-wide SELECT, replaced by
-- column privileges (whole), and the SELECT of their own that masked columns had (cols)
CREATE TABLE IF NOT EXISTS authz.masked_tables (
  tbl   text,
  role  text,
  whole boolean NOT NULL,
  cols  text[] NOT NULL,
  PRIMARY KEY (tbl, role));
REVOKE ALL ON authz.changes, authz.requests, authz.reviews, authz.review_items, authz.masked_tables FROM PUBLIC;

-- Every policy the rowstile command applied or removed, with the rowstile version that did it
CREATE TABLE IF NOT EXISTS authz.policy_versions (
  id      bigserial PRIMARY KEY,
  at      timestamptz NOT NULL DEFAULT now(),
  by_role text NOT NULL DEFAULT current_user,
  action  text NOT NULL CHECK (action IN ('apply', 'remove')),
  policy  text,
  files   jsonb NOT NULL DEFAULT '{}',
  version text NOT NULL,
  -- what the migrations' lock file said about this policy (its hash), for the next migration to check
  lock    text);
REVOKE ALL ON authz.policy_versions FROM PUBLIC;

-- Request context for conditions: SET LOCAL authz_ctx.mfa = 'yes', then {authz.ctx('mfa') = 'yes'}
CREATE OR REPLACE FUNCTION authz.ctx(key text) RETURNS text LANGUAGE sql STABLE AS
  $$ SELECT current_setting('authz_ctx.' || key, true) $$;

-- Link tokens the request presents: SET LOCAL authz_ctx.links = '<token>,<token>'
CREATE OR REPLACE FUNCTION authz.link_hashes() RETURNS text[] LANGUAGE sql STABLE AS $$
  SELECT coalesce(array_agg(encode(sha256(convert_to(btrim(x), 'UTF8')), 'hex')), '{}')
  FROM unnest(string_to_array(nullif(current_setting('authz_ctx.links', true), ''), ',')) x
  WHERE btrim(x) <> '' $$;"""

# Functions each apply recreates (dropped first, whatever their old signature).
GENERATED_FUNCTIONS = (
    "act_as",
    "can",
    "list",
    "perms",
    "perms_of",
    "share",
    "unshare",
    "verify",
    "create_link",
    "principal",
    "create_role",
    "set_role_permissions",
    "delete_role",
    "roles_of",
    "who",
    "explain",
    "list_shares",
    "create_api_key",
    "list_api_keys",
    "revoke_api_key",
    "login_key",
    "login_jwt",
    "view_as",
    "sync_members",
    "changes_since",
    "trim_changes",
    "trim_audit",
    "request_access",
    "pending_requests",
    "decide_request",
    "cancel_request",
    "break_glass",
    "start_review",
    "review_items",
    "review_decide",
    "close_review",
    "check_invariants",
    "lint",
    "connection_check",
    "explain_rule",
    "who_among",
    "list_links",
    "revoke_link",
)
