"""A SCIM endpoint answered in SQL (RFC 7644): authz.scim takes a request's parts (its method, its path below
the route, its query string, its body, its bearer token) and answers a status, a body and a location, so an SDK's
route holds none of the protocol; authz.set_scim names what it reads. Groups and users: read, listed, found by a
filter, made, replaced, patched and deleted."""

from __future__ import annotations

from .identity import DEF, IdentityMixin
from .parse import cols
from .sqlutil import lit, q, qt

# what authz.set_scim takes, in the order its messages list them
SETTINGS = (
    "principal",
    "group",
    "group_name",
    "group_external_id",
    "group_function",
    "user_name",
    "user_external_id",
    "user_active",
    "user_resource",
    "user_function",
    "page",
)

# The helpers that name authz_int run as the owner whoever calls ({DEF}), as its other functions do: a body in a
# string is read as whoever runs it, and the app role may not name that schema.
# Refusals are answers (a status and SCIM's error body), never errors: a route answers what comes back. What is
# an error stays one, for the app to see and its transaction to undo: settings that no longer hold, a function of the
# app's that fails with something that is no refusal of the request, a write that could not be serialized.
SCIM_SQL = r"""-- SCIM (RFC 7644) answered in SQL: an identity provider's requests, as a route hands them on (authz.scim)

-- what a request is answered: a status, a body (none for 204) and, for what was made, where it is below the route
CREATE TYPE authz_int.scim_answer AS (status int, body jsonb, location text);
-- an error's body as SCIM writes it (RFC 7644, 3.12): the status as a text, the scimType where the RFC names one
CREATE FUNCTION authz_int.scim_error(p_status int, p_type text, p_detail text) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $f$
  SELECT jsonb_strip_nulls(jsonb_build_object('schemas', jsonb_build_array('urn:ietf:params:scim:api:messages:2.0:Error'),
                                              'status', p_status::text, 'scimType', p_type, 'detail', p_detail)) $f$;
-- a refusal of rowstile's own, its words ending with their code
CREATE FUNCTION authz_int.scim_no(p_status int, p_type text, p_detail text) RETURNS authz_int.scim_answer
LANGUAGE sql IMMUTABLE {DEF} AS $f$
  SELECT ROW(p_status, authz_int.scim_error(p_status, p_type, p_detail || ' (rowstile help AZ721)'), NULL)::authz_int.scim_answer $f$;
-- ids as a list of members
CREATE FUNCTION authz_int.scim_values(p_ids text[]) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $f$
  SELECT coalesce(jsonb_agg(jsonb_build_object('value', x.id) ORDER BY x.i), '[]'::jsonb)
  FROM unnest(p_ids) WITH ORDINALITY x(id, i) $f$;

-- A part of a URL read: + is a space, %41 the byte 41 (the bytes then read as UTF-8); a % that starts no escape
-- is a %
CREATE FUNCTION authz_int.url_decode(p_text text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $f$
  SELECT convert_from(decode(coalesce(string_agg(CASE WHEN x.part[1] ~ '^%..$' THEN substr(x.part[1], 2)
                                                      ELSE encode(convert_to(x.part[1], 'UTF8'), 'hex') END, '' ORDER BY x.i), ''),
                             'hex'), 'UTF8')
  FROM regexp_matches(replace(p_text, '+', ' '), '%[0-9A-Fa-f]{2}|[^%]+|%', 'g') WITH ORDINALITY x(part, i) $f$;
-- A query string's parameters, by their names in lower case (a name given twice keeps its last value). NULL for
-- one whose escapes are no text (bytes that are no UTF-8, or that this database's encoding has no character for)
CREATE FUNCTION authz_int.scim_query(p_query text) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE {DEF} AS $f$
BEGIN
  RETURN (SELECT coalesce(jsonb_object_agg(lower(authz_int.url_decode(split_part(x.pair, '=', 1))),
                                           authz_int.url_decode(substr(x.pair, length(split_part(x.pair, '=', 1)) + 2)) ORDER BY x.i),
                          '{}'::jsonb)
          FROM unnest(string_to_array(coalesce(p_query, ''), '&')) WITH ORDINALITY x(pair, i) WHERE x.pair <> '');
EXCEPTION WHEN character_not_in_repertoire OR untranslatable_character THEN
  RETURN NULL;
END $f$;
-- A filter read: `attribute eq "value"`, joined by `and`, the attributes and the operators in any case (what
-- Microsoft Entra ID and Okta send), as a list of [attribute in lower case, value]. NULL for anything else
CREATE FUNCTION authz_int.scim_filter(p_filter text) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v_rest text := p_filter; v_terms jsonb := '[]'; v_term text[];
BEGIN
  LOOP
    v_term := regexp_match(v_rest, E'^[[:space:]]*([A-Za-z][A-Za-z0-9_.:$-]*)[[:space:]]+[eE][qQ][[:space:]]+("(?:[^"\\\\]|\\\\.)*")[[:space:]]*(?:[aA][nN][dD][[:space:]]+(.*))?$');
    IF v_term IS NULL THEN
      RETURN NULL;
    END IF;
    v_terms := v_terms || jsonb_build_array(jsonb_build_array(lower(v_term[1]), v_term[2]::jsonb));
    IF v_term[3] IS NULL THEN
      RETURN v_terms;
    END IF;
    v_rest := v_term[3];
  END LOOP;
EXCEPTION WHEN invalid_text_representation THEN   -- a value with an escape JSON doesn't have
  RETURN NULL;
END $f$;

-- A column the settings name, of a table of the app's: its type. A column that is gone since they were set is an
-- error, saying so
CREATE FUNCTION authz_int.scim_column(p_table text, p_column text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v_type text;
BEGIN
  SELECT format_type(a.atttypid, a.atttypmod) INTO v_type FROM pg_attribute a
  WHERE a.attrelid = to_regclass(p_table) AND a.attname = p_column AND a.attnum > 0 AND NOT a.attisdropped;
  IF v_type IS NULL THEN
    RAISE EXCEPTION 'the SCIM settings name the column % of %, which has none of that name now: set them again (authz.set_scim)',
      p_column, to_regclass(p_table) USING ERRCODE = 'object_not_in_prerequisite_state', HINT = 'rowstile help AZ722';
  END IF;
  RETURN v_type;
END $f$;

-- The members a request names (a list of {"value": a user's id}, or one of them), as ids the database writes.
-- p_there: each is a user's row, held until the transaction ends (a member added; one removed needs no row). why:
-- what is wrong with the first that isn't one
CREATE FUNCTION authz_int.scim_members(p_value jsonb, p_there boolean, OUT ids text[], OUT why text)
LANGUAGE plpgsql {DEF} AS $f$
DECLARE v_member jsonb; v_id text;
BEGIN
  ids := '{}';
  FOR v_member IN SELECT x.member FROM jsonb_array_elements(CASE jsonb_typeof(p_value) WHEN 'array' THEN p_value
                                                               WHEN 'object' THEN jsonb_build_array(p_value)
                                                               ELSE '[null]' END) WITH ORDINALITY x(member, i) ORDER BY x.i LOOP
    v_id := CASE WHEN jsonb_typeof(v_member->'value') IN ('string', 'number') THEN v_member->>'value' END;
    IF v_id IS NULL THEN
      why := 'a member is {"value": a user''s id}';
    ELSIF lower(coalesce(v_member->>'type', 'user')) <> 'user' THEN
      why := format('member %s is a %s: a group''s members are users here', v_id, v_member->>'type');
    ELSIF p_there AND NOT authz_int.hold('user', authz_int.canon('user', v_id)) THEN
      why := format('there is no user %s', v_id);
    END IF;
    EXIT WHEN why IS NOT NULL;
    v_id := authz_int.canon('user', v_id);
    IF v_id <> ALL (ids) THEN
      ids := ids || v_id;
    END IF;
  END LOOP;
END $f$;

-- A PATCH's operations applied to a group as it is (RFC 7644, 3.5.2): its members, its name, its externalId as
-- they are then; touched: an operation named the members. An operation without a path carries attributes in its
-- value, each read as an operation on it. scim_type and why: the first operation that can't be applied, and nothing
-- of the PATCH is
CREATE FUNCTION authz_int.scim_group_patch(p_operations jsonb, p_members text[], p_name text, p_external_id text,
  OUT members text[], OUT name text, OUT external_id text, OUT touched boolean, OUT scim_type text, OUT why text)
LANGUAGE plpgsql {DEF} AS $f$
DECLARE o record; m record; v_text boolean;
BEGIN
  members := p_members; name := p_name; external_id := p_external_id; touched := false;
  IF jsonb_typeof(p_operations) IS DISTINCT FROM 'array' OR jsonb_array_length(p_operations) = 0 THEN
    scim_type := 'invalidSyntax'; why := 'a PATCH carries Operations: a list of op, path and value';
    RETURN;
  END IF;
  FOR o IN
    SELECT lower(x.operation->>'op') AS op, coalesce(x.operation->>'path', a.key) AS path, x.operation->>'path' IS NOT NULL AS said,
           CASE WHEN x.operation->>'path' IS NULL THEN a.value ELSE x.operation->'value' END AS value
    FROM jsonb_array_elements(p_operations) WITH ORDINALITY x(operation, i)
    LEFT JOIN LATERAL jsonb_each(CASE WHEN x.operation->>'path' IS NULL AND jsonb_typeof(x.operation->'value') = 'object'
                                           AND lower(x.operation->>'op') IS DISTINCT FROM 'remove'
                                      THEN x.operation->'value' END) a ON true
    ORDER BY x.i, a.key
  LOOP
    v_text := jsonb_typeof(o.value) IS NOT DISTINCT FROM 'string';
    IF o.op IS NULL OR o.op NOT IN ('add', 'remove', 'replace') THEN
      scim_type := 'invalidSyntax'; why := format('op is add, remove or replace, not %s', coalesce(o.op, 'nothing'));
    ELSIF o.path IS NULL AND o.op = 'remove' THEN
      scim_type := 'noTarget'; why := 'a remove names what it removes: a path';
    ELSIF o.path IS NULL THEN
      scim_type := 'invalidValue'; why := 'an operation with no path carries its attributes in value';
    ELSIF lower(o.path) = 'members' AND o.op = 'remove' AND coalesce(jsonb_typeof(o.value), 'null') = 'null' THEN
      members := '{}'; touched := true;
    ELSIF lower(o.path) = 'members' THEN
      SELECT * INTO m FROM authz_int.scim_members(o.value, o.op <> 'remove');
      scim_type := CASE WHEN m.why IS NOT NULL THEN 'invalidValue' END; why := m.why;
      members := CASE o.op WHEN 'replace' THEN m.ids
                           WHEN 'add' THEN members || ARRAY(SELECT x.id FROM unnest(m.ids) WITH ORDINALITY x(id, i)
                                                            WHERE x.id <> ALL (members) ORDER BY x.i)
                           ELSE ARRAY(SELECT x.id FROM unnest(members) WITH ORDINALITY x(id, i)
                                      WHERE x.id <> ALL (m.ids) ORDER BY x.i) END;
      touched := true;
    ELSIF o.path ~* '^members[[][[:space:]]*value[[:space:]]+eq[[:space:]]+"[^"]*"[[:space:]]*[]]$' AND o.op = 'remove' THEN
      members := array_remove(members, authz_int.canon('user', split_part(o.path, '"', 2))); touched := true;
    ELSIF o.path ~* '^members[[]' THEN
      scim_type := 'invalidPath'; why := 'a path names one member for a remove alone, as members[value eq "id"]';
    ELSIF lower(o.path) = 'displayname' AND o.op <> 'remove' AND v_text AND o.value #>> '{}' <> '' THEN
      name := o.value #>> '{}';
    ELSIF lower(o.path) = 'displayname' THEN
      scim_type := 'invalidValue'; why := 'displayName: a group has a name, a text that isn''t empty';
    ELSIF lower(o.path) = 'externalid' AND (o.op = 'remove' OR v_text) THEN
      external_id := CASE WHEN o.op <> 'remove' THEN o.value #>> '{}' END;
    ELSIF lower(o.path) = 'externalid' THEN
      scim_type := 'invalidValue'; why := 'externalId: a text';
    ELSIF o.said OR lower(o.path) NOT IN ('id', 'schemas', 'meta') THEN   -- (what a value with no path says of those is no change)
      scim_type := 'invalidPath';
      why := format('%s is nothing of a group a PATCH changes here (displayName, externalId, members)', o.path);
    END IF;
    EXIT WHEN why IS NOT NULL;
  END LOOP;
END $f$;

-- The groups or the users (p_kind) the settings open, as SCIM writes them, in the order of their keys, a page of
-- them at most: those a filter's terms name ([[attribute, value], ...]; none: all), with how many there are in all.
-- A value is compared as the column's type compares, so an index on the column finds it; one that is no value of
-- that type finds nothing. A user is what the provider wrote (the column user_resource names, without a password),
-- and over it what the columns the settings name say now: its userName, its externalId, whether it is active
CREATE FUNCTION authz_int.scim_rows(p_settings jsonb, p_kind text, p_terms jsonb, p_members boolean, OUT total bigint, OUT resources jsonb)
LANGUAGE plpgsql STABLE {DEF} AS $f$
DECLARE v_type text := CASE p_kind WHEN 'user' THEN 'user' ELSE split_part(p_settings->>'group', '.', 1) END; t authz_int.types;
        v_term jsonb; v_id text; v_values text[] := '{}'; v_where text := ''; v_order text;
        v_name text := p_settings->>(p_kind || '_name'); v_external text := p_settings->>(p_kind || '_external_id');
        v_active text := CASE p_kind WHEN 'user' THEN p_settings->>'user_active' END;
        v_resource text := CASE p_kind WHEN 'user' THEN p_settings->>'user_resource' END;
        v_column text; v_column_type text;
BEGIN
  SELECT * INTO t FROM authz_int.types x WHERE x.name = v_type;
  FOREACH v_column IN ARRAY ARRAY[v_name, v_external, v_active, v_resource] LOOP
    IF v_column IS NOT NULL THEN
      PERFORM authz_int.scim_column(t.tbl, v_column);
    END IF;
  END LOOP;
  FOR v_term IN SELECT x.term FROM jsonb_array_elements(p_terms) WITH ORDINALITY x(term, i) ORDER BY x.i LOOP
    IF v_term->>0 = 'id' THEN
      -- (the key's type by a subquery, as authz_int.hold asks it)
      IF pg_input_is_valid(v_term->>1, (SELECT x.keytype FROM authz_int.types x WHERE x.name = v_type))
         AND authz_int.canon(v_type, v_term->>1) IS NOT DISTINCT FROM coalesce(v_id, authz_int.canon(v_type, v_term->>1)) THEN
        v_id := authz_int.canon(v_type, v_term->>1);
        v_where := v_where || ' AND ' || t.find;
      ELSE
        v_where := v_where || ' AND false';
      END IF;
    ELSE
      v_column := CASE WHEN v_term->>0 = 'externalid' THEN v_external ELSE v_name END;
      IF v_column IS NULL THEN   -- (an externalId, and the settings name no column for it: none is found by one)
        v_where := v_where || ' AND false';
      ELSE
        v_column_type := authz_int.scim_column(t.tbl, v_column);
        v_values := v_values || (v_term->>1);
        v_where := v_where || format(' AND x.%I = (CASE WHEN pg_input_is_valid($2[%s], (SELECT %L)) THEN $2[%s] END)::%s',
                                     v_column, cardinality(v_values), v_column_type, cardinality(v_values), v_column_type);
      END IF;
    END IF;
  END LOOP;
  v_order := (SELECT string_agg(format('x.%I', c.name), ', ' ORDER BY c.i) FROM unnest(string_to_array(t.pk, ', ')) WITH ORDINALITY c(name, i));
  -- (the row's own columns are named in the innermost query alone, where nothing else has a name)
  EXECUTE format(
    'SELECT coalesce(max(g.n), 0), coalesce(jsonb_agg(%s ORDER BY g.i), ''[]''::jsonb) '
    || 'FROM (SELECT %s AS id, x.%I::text AS name, %s AS external_id, %s AS active, %s AS resource, '
    || 'count(*) OVER () AS n, row_number() OVER (ORDER BY %s) AS i FROM %s x WHERE true%s ORDER BY %s LIMIT %s) g',
    CASE p_kind WHEN 'user' THEN
      format('(g.resource - ''password'' - ''id'' - ''meta'' - ''userName''%s%s) || jsonb_strip_nulls(jsonb_build_object('
             || '''schemas'', coalesce(g.resource->''schemas'', jsonb_build_array(''urn:ietf:params:scim:schemas:core:2.0:User'')), '
             || '''id'', g.id, ''userName'', g.name, ''externalId'', g.external_id, '
             || '''active'', coalesce(to_jsonb(g.active), g.resource->''active'', ''true''::jsonb), '
             || '''meta'', jsonb_build_object(''resourceType'', ''User'')))',
             CASE WHEN v_external IS NOT NULL THEN ' - ''externalId''' ELSE '' END,
             CASE WHEN v_active IS NOT NULL THEN ' - ''active''' ELSE '' END)
    ELSE
      'jsonb_strip_nulls(jsonb_build_object('
      || '''schemas'', jsonb_build_array(''urn:ietf:params:scim:schemas:core:2.0:Group''), ''id'', g.id, ''externalId'', g.external_id, '
      || '''displayName'', g.name, ''meta'', jsonb_build_object(''resourceType'', ''Group''))) '
      || '|| CASE WHEN $4 THEN jsonb_build_object(''members'', authz_int.scim_values(authz_int.members_of($3, g.id))) ELSE ''{}''::jsonb END'
    END,
    t.id_of, v_name, CASE WHEN v_external IS NULL THEN 'NULL::text' ELSE format('x.%I::text', v_external) END,
    CASE WHEN v_active IS NULL THEN 'NULL::boolean' ELSE format('x.%I', v_active) END,
    CASE WHEN v_resource IS NULL THEN '''{}''::jsonb' ELSE format('coalesce(x.%I, ''{}''::jsonb)', v_resource) END,
    v_order, t.tbl, v_where, v_order, coalesce((p_settings->>'page')::int, 100))
  INTO total, resources USING v_id, v_values, p_settings->>'group', p_members;
END $f$;

-- A group's row held until the transaction ends: two requests that change one group's members go one after the
-- other, the second from the members the first left (a lock that lets rows that name the group be written)
CREATE FUNCTION authz_int.scim_hold(p_type text, p_id text) RETURNS void
LANGUAGE plpgsql {DEF} AS $f$
DECLARE t authz_int.types;
BEGIN
  SELECT * INTO t FROM authz_int.types x WHERE x.name = p_type;
  IF pg_input_is_valid(p_id, (SELECT x.keytype FROM authz_int.types x WHERE x.name = p_type)) THEN
    EXECUTE format('SELECT 1 FROM %s x WHERE %s FOR NO KEY UPDATE', t.tbl, t.find) USING p_id;
  END IF;
END $f$;

-- The app's function for a group or a user (the settings name it) called: p_id NULL makes the row, p_resource
-- NULL deletes it. Its answer, the row's key, or the refusal a route answers: 409 where a key or a name is another
-- row's, 400 with the function's own words for what it raised and for what a constraint refused. Anything else it
-- fails with is an error. It runs as the policy's owner, so it must be the owner's still: a role that may write its
-- body would otherwise run its own code with the owner's rights
CREATE FUNCTION authz_int.scim_call(p_function text, p_type text, p_id text, p_resource jsonb,
  OUT key text, OUT refusal authz_int.scim_answer)
LANGUAGE plpgsql {DEF} AS $f$
BEGIN
  IF NOT coalesce((SELECT r.rolsuper OR pg_has_role(p.proowner, n.nspowner, 'MEMBER')
                   FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner, pg_namespace n
                   WHERE p.oid = to_regprocedure(p_function || '(text, jsonb)') AND n.nspname = 'authz_int'), false) THEN
    RAISE EXCEPTION 'the function % the SCIM settings name is gone, or is no longer the policy''s owner''s: set them again (authz.set_scim)',
      p_function USING ERRCODE = 'object_not_in_prerequisite_state', HINT = 'rowstile help AZ722';
  END IF;
  BEGIN
    EXECUTE 'SELECT ' || p_function || '($1, $2)' INTO key USING p_id, p_resource;
  EXCEPTION
    WHEN unique_violation THEN
      refusal := ROW(409, authz_int.scim_error(409, 'uniqueness', SQLERRM), NULL)::authz_int.scim_answer;
      RETURN;
    WHEN raise_exception OR data_exception OR integrity_constraint_violation THEN
      refusal := ROW(400, authz_int.scim_error(400, 'invalidValue', SQLERRM), NULL)::authz_int.scim_answer;
      RETURN;
  END;
  IF p_resource IS NOT NULL AND NOT coalesce(authz_int.hold(p_type, authz_int.canon(p_type, key)), false) THEN
    RAISE EXCEPTION '% answered %, which is no %''s key: the function the SCIM settings name answers the key of the row it made or changed',
      p_function, coalesce(key, 'nothing'), p_type USING ERRCODE = 'object_not_in_prerequisite_state', HINT = 'rowstile help AZ722';
  END IF;
  key := authz_int.canon(p_type, key);
END $f$;

-- A request for the groups (p_id NULL) or for one: read, listed, made, replaced, patched, deleted. Everything a
-- request says is read before anything is written, the app's function is called before the members are, and what
-- fails after that is an error: so a request is done whole or not at all
CREATE FUNCTION authz_int.scim_group(p_settings jsonb, p_method text, p_id text, p_query jsonb, p_body jsonb)
RETURNS authz_int.scim_answer
LANGUAGE plpgsql {DEF} AS $f$
DECLARE v_type text := split_part(p_settings->>'group', '.', 1); v_relation text := split_part(p_settings->>'group', '.', 2);
        v_function text := p_settings->>'group_function';
        v_members_too boolean := lower(coalesce(p_query->>'excludedattributes', '')) !~ '(^|,)[[:space:]]*members[[:space:]]*(,|$)';
        v_terms jsonb := '[]'; v_id text; v_now jsonb; v_name text; v_external text; v_members text[]; v_resource jsonb;
        g record; p record; m record; c record;
BEGIN
  IF NOT authz_int.takes_members(p_settings->>'group') THEN   -- (none named, or one the policy no longer has)
    RETURN authz_int.scim_no(501, NULL, 'the SCIM settings name no group to serve (authz.set_scim: group, a relation authz.sync_members takes)');
  ELSIF p_method = 'GET' AND p_id IS NULL THEN
    IF p_query ? 'filter' THEN
      v_terms := authz_int.scim_filter(p_query->>'filter');
    END IF;
    IF v_terms IS NULL OR EXISTS (SELECT 1 FROM jsonb_array_elements(v_terms) x(term)
                                  WHERE x.term->>0 NOT IN ('displayname', 'externalid', 'id')) THEN
      RETURN authz_int.scim_no(400, 'invalidFilter',
                               'a filter here is attribute eq "value", joined by and, on displayName, externalId and id');
    END IF;
    SELECT * INTO g FROM authz_int.scim_rows(p_settings, 'group', v_terms, v_members_too);
    RETURN ROW(200, jsonb_build_object('schemas', jsonb_build_array('urn:ietf:params:scim:api:messages:2.0:ListResponse'),
                                       'totalResults', g.total, 'itemsPerPage', jsonb_array_length(g.resources),
                                       'startIndex', 1, 'Resources', g.resources), NULL)::authz_int.scim_answer;
  ELSIF (p_id IS NULL) <> (p_method = 'POST') OR p_method NOT IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE') THEN
    RETURN authz_int.scim_no(405, NULL, format('%s is no request Groups%s takes', p_method, coalesce('/' || p_id, '')));
  END IF;
  IF p_id IS NOT NULL THEN
    v_id := authz_int.canon(v_type, p_id);
    IF p_method <> 'GET' THEN
      PERFORM authz_int.scim_hold(v_type, v_id);
    END IF;
    SELECT x.resources->0 INTO v_now FROM authz_int.scim_rows(p_settings, 'group', jsonb_build_array(jsonb_build_array('id', v_id)), true) x;
    IF v_now IS NULL THEN
      RETURN authz_int.scim_no(404, NULL, 'no group ' || p_id);
    ELSIF p_method = 'GET' THEN
      RETURN ROW(200, CASE WHEN v_members_too THEN v_now ELSE v_now - 'members' END, NULL)::authz_int.scim_answer;
    END IF;
  END IF;
  -- the group as the request leaves it: its name, its externalId, its members (NULL: as they are), and what the
  -- app's function gets of it (a PATCH: the group with the operations applied; else the body as it was sent)
  IF p_method = 'PATCH' THEN
    SELECT * INTO p FROM authz_int.scim_group_patch(p_body->'Operations',
      ARRAY(SELECT x.member->>'value' FROM jsonb_array_elements(v_now->'members') WITH ORDINALITY x(member, i) ORDER BY x.i),
      v_now->>'displayName', v_now->>'externalId');
    IF p.why IS NOT NULL THEN
      RETURN authz_int.scim_no(400, p.scim_type, p.why);
    END IF;
    v_name := p.name; v_external := p.external_id; v_members := CASE WHEN p.touched THEN p.members END;
    v_resource := jsonb_strip_nulls(v_now || jsonb_build_object('displayName', v_name, 'externalId', v_external))
                  || jsonb_build_object('members', authz_int.scim_values(p.members));
  ELSIF p_method <> 'DELETE' THEN
    v_resource := p_body;
    v_name := CASE WHEN jsonb_typeof(p_body->'displayName') = 'string' THEN p_body->>'displayName' END;
    v_external := CASE WHEN p_body ? 'externalId' THEN p_body->>'externalId' ELSE v_now->>'externalId' END;
    IF coalesce(v_name, '') = '' THEN
      RETURN authz_int.scim_no(400, 'invalidValue', 'displayName: a group has a name, a text that isn''t empty');
    ELSIF jsonb_typeof(p_body->'members') <> 'null' THEN   -- (members not said, a PUT's too: they stay as they are)
      SELECT * INTO m FROM authz_int.scim_members(p_body->'members', true);
      IF m.why IS NOT NULL THEN
        RETURN authz_int.scim_no(400, 'invalidValue', m.why);
      END IF;
      v_members := m.ids;
    END IF;
  END IF;
  -- its row is the app's to write, through the function the settings name: a new group, a deleted one, a whole
  -- one put, and a name or an externalId (where the settings name its column) that is no longer the row's
  IF p_method IN ('POST', 'DELETE') OR v_name IS DISTINCT FROM (v_now->>'displayName')
     OR (p_settings ? 'group_external_id' AND v_external IS DISTINCT FROM (v_now->>'externalId'))
     OR (p_method = 'PUT' AND v_function IS NOT NULL) THEN
    IF v_function IS NULL THEN
      RETURN authz_int.scim_no(501, NULL, 'the SCIM settings name no function that makes, changes or deletes a group (authz.set_scim: group_function)');
    END IF;
    SELECT * INTO c FROM authz_int.scim_call(v_function, v_type, v_id, v_resource);
    IF (c.refusal).status IS NOT NULL THEN
      RETURN c.refusal;
    ELSIF p_method = 'DELETE' THEN
      RETURN ROW(204, NULL, NULL)::authz_int.scim_answer;
    END IF;
    v_id := c.key;
  END IF;
  IF v_members IS NOT NULL THEN
    PERFORM authz.sync_members(v_type, v_id, v_relation, v_members);
  END IF;
  IF p_method = 'PATCH' THEN
    RETURN ROW(204, NULL, NULL)::authz_int.scim_answer;
  END IF;
  SELECT x.resources->0 INTO v_now FROM authz_int.scim_rows(p_settings, 'group', jsonb_build_array(jsonb_build_array('id', v_id)), true) x;
  RETURN ROW(CASE p_method WHEN 'POST' THEN 201 ELSE 200 END, v_now, CASE p_method WHEN 'POST' THEN 'Groups/' || v_id END)::authz_int.scim_answer;
END $f$;

-- A PATCH's operations applied to a user as it is (RFC 7644, 3.5.2), each on what its path names: an attribute
-- (active), a part of one (name.familyName), the values of a list chosen by one of their parts (emails[type eq
-- "work"]) or a part of those (emails[type eq "work"].value), in the resource or in a schema's part of it (the
-- path begins with the schema's URN). Attribute names are read in any case. A value a replace or an add finds no
-- place for in a list is added to it, with the part that chooses it. An operation without a path carries attributes
-- in its value, each read as an operation on it. scim_type and why: the first operation that can't be applied
CREATE FUNCTION authz_int.scim_patch(p_resource jsonb, p_operations jsonb, OUT resource jsonb, OUT scim_type text, OUT why text)
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE o record; v_path text[]; v_chosen text[]; v_in jsonb; v_key text; v_now jsonb; v_new jsonb;
BEGIN
  resource := p_resource;
  IF jsonb_typeof(p_operations) IS DISTINCT FROM 'array' OR jsonb_array_length(p_operations) = 0 THEN
    scim_type := 'invalidSyntax'; why := 'a PATCH carries Operations: a list of op, path and value';
    RETURN;
  END IF;
  FOR o IN
    SELECT lower(x.operation->>'op') AS op, coalesce(x.operation->>'path', a.key) AS path, x.operation->>'path' IS NOT NULL AS said,
           CASE WHEN x.operation->>'path' IS NULL THEN a.value ELSE x.operation->'value' END AS value
    FROM jsonb_array_elements(p_operations) WITH ORDINALITY x(operation, i)
    LEFT JOIN LATERAL jsonb_each(CASE WHEN x.operation->>'path' IS NULL AND jsonb_typeof(x.operation->'value') = 'object'
                                           AND lower(x.operation->>'op') IS DISTINCT FROM 'remove'
                                      THEN x.operation->'value' END) a ON true
    ORDER BY x.i, a.key
  LOOP
    v_path := regexp_match(o.path, '^(?:(urn:.+):)?([A-Za-z$][A-Za-z0-9_$-]*)(?:[[]([^]]*)[]])?(?:[.]([A-Za-z$][A-Za-z0-9_$-]*))?$');
    v_chosen := regexp_match(v_path[3], '^[[:space:]]*([A-Za-z$][A-Za-z0-9_$-]*)[[:space:]]+[eE][qQ][[:space:]]+"([^"]*)"[[:space:]]*$');
    IF o.op IS NULL OR o.op NOT IN ('add', 'remove', 'replace') THEN
      scim_type := 'invalidSyntax'; why := format('op is add, remove or replace, not %s', coalesce(o.op, 'nothing'));
    ELSIF o.path IS NULL AND o.op = 'remove' THEN
      scim_type := 'noTarget'; why := 'a remove names what it removes: a path';
    ELSIF o.path IS NULL THEN
      scim_type := 'invalidValue'; why := 'an operation with no path carries its attributes in value';
    ELSIF o.op <> 'remove' AND coalesce(jsonb_typeof(o.value), 'null') = 'null' THEN
      scim_type := 'invalidValue'; why := format('%s: an add and a replace carry a value', o.path);
    ELSIF NOT o.said AND o.path LIKE 'urn:%' AND jsonb_typeof(o.value) = 'object' THEN   -- (a schema's part, whole)
      resource := resource || jsonb_build_object(o.path, CASE WHEN jsonb_typeof(resource->(o.path)) = 'object' THEN resource->(o.path)
                                                              ELSE '{}' END || o.value);
    ELSIF v_path IS NULL OR (v_path[3] IS NOT NULL AND v_chosen IS NULL) THEN
      scim_type := 'invalidPath';
      why := format('%s is no path read here: attribute, attribute.part, attribute[part eq "value"] or attribute[part eq "value"].part', o.path);
    ELSE
      v_in := CASE WHEN v_path[1] IS NULL THEN resource
                   WHEN jsonb_typeof(resource->(v_path[1])) = 'object' THEN resource->(v_path[1]) ELSE '{}' END;
      v_key := coalesce((SELECT k.name FROM jsonb_object_keys(v_in) k(name) WHERE lower(k.name) = lower(v_path[2]) LIMIT 1), v_path[2]);
      v_now := v_in->v_key;
      IF v_chosen IS NOT NULL THEN
        v_now := CASE WHEN jsonb_typeof(v_now) = 'array' THEN v_now ELSE '[]' END;
        v_new := (SELECT coalesce(jsonb_agg(CASE WHEN x.item->>(v_chosen[1]) IS DISTINCT FROM v_chosen[2] THEN x.item
                                                 WHEN v_path[4] IS NULL THEN o.value
                                                 WHEN o.op = 'remove' THEN x.item - v_path[4]
                                                 ELSE x.item || jsonb_build_object(v_path[4], o.value) END ORDER BY x.i)
                                   FILTER (WHERE NOT (o.op = 'remove' AND v_path[4] IS NULL
                                                      AND x.item->>(v_chosen[1]) IS NOT DISTINCT FROM v_chosen[2])), '[]')
                  FROM jsonb_array_elements(v_now) WITH ORDINALITY x(item, i));
        IF o.op <> 'remove' AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(v_now) x(item) WHERE x.item->>(v_chosen[1]) = v_chosen[2]) THEN
          v_new := v_new || jsonb_build_array(CASE WHEN v_path[4] IS NULL THEN o.value
                                                   ELSE jsonb_build_object(v_chosen[1], v_chosen[2], v_path[4], o.value) END);
        END IF;
      ELSIF v_path[4] IS NOT NULL THEN
        v_now := CASE WHEN jsonb_typeof(v_now) = 'object' THEN v_now ELSE '{}' END;
        v_new := CASE WHEN o.op = 'remove' THEN v_now - v_path[4] ELSE v_now || jsonb_build_object(v_path[4], o.value) END;
      ELSIF o.op = 'remove' THEN
        v_new := NULL;
      ELSIF o.op = 'add' AND jsonb_typeof(v_now) = jsonb_typeof(o.value) AND jsonb_typeof(v_now) IN ('array', 'object') THEN
        v_new := v_now || o.value;   -- (an add joins a list's values, and a complex attribute's parts)
      ELSE
        v_new := o.value;
      END IF;
      v_in := CASE WHEN v_new IS NULL THEN v_in - v_key ELSE v_in || jsonb_build_object(v_key, v_new) END;
      resource := CASE WHEN v_path[1] IS NULL THEN v_in ELSE resource || jsonb_build_object(v_path[1], v_in) END;
    END IF;
    EXIT WHEN why IS NOT NULL;
  END LOOP;
END $f$;

-- A request for the users (p_id NULL) or for one. rowstile reads them: by id, listed, found by userName, externalId
-- or id. The app's function (the setting user_function) makes, changes and deletes them: it gets the user as the
-- request leaves it (a POST's or a PUT's body; a PATCH's operations applied to the user as it is), without a
-- password, active as true or false whichever way it was written. A userName is one user's (409). A user who is
-- no longer active stays, answered as such: what such a user may do is the policy's to say (type user ... where)
CREATE FUNCTION authz_int.scim_user(p_settings jsonb, p_method text, p_id text, p_query jsonb, p_body jsonb)
RETURNS authz_int.scim_answer
LANGUAGE plpgsql {DEF} AS $f$
DECLARE v_function text := p_settings->>'user_function'; v_terms jsonb := '[]'; v_id text; v_now jsonb; v_new jsonb;
        g record; p record; c record;
BEGIN
  IF p_settings->>'user_name' IS NULL THEN
    RETURN authz_int.scim_no(501, NULL, 'the SCIM settings name no column for a user''s userName (authz.set_scim: user_name)');
  ELSIF p_method = 'GET' AND p_id IS NULL THEN
    IF p_query ? 'filter' THEN
      v_terms := authz_int.scim_filter(p_query->>'filter');
    END IF;
    IF v_terms IS NULL OR EXISTS (SELECT 1 FROM jsonb_array_elements(v_terms) x(term)
                                  WHERE x.term->>0 NOT IN ('username', 'externalid', 'id')) THEN
      RETURN authz_int.scim_no(400, 'invalidFilter',
                               'a filter here is attribute eq "value", joined by and, on userName, externalId and id');
    END IF;
    SELECT * INTO g FROM authz_int.scim_rows(p_settings, 'user', v_terms, false);
    RETURN ROW(200, jsonb_build_object('schemas', jsonb_build_array('urn:ietf:params:scim:api:messages:2.0:ListResponse'),
                                       'totalResults', g.total, 'itemsPerPage', jsonb_array_length(g.resources),
                                       'startIndex', 1, 'Resources', g.resources), NULL)::authz_int.scim_answer;
  ELSIF (p_id IS NULL) <> (p_method = 'POST') OR p_method NOT IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE') THEN
    RETURN authz_int.scim_no(405, NULL, format('%s is no request Users%s takes', p_method, coalesce('/' || p_id, '')));
  END IF;
  IF p_id IS NOT NULL THEN
    v_id := authz_int.canon('user', p_id);
    IF p_method <> 'GET' THEN
      PERFORM authz_int.scim_hold('user', v_id);
    END IF;
    SELECT x.resources->0 INTO v_now FROM authz_int.scim_rows(p_settings, 'user', jsonb_build_array(jsonb_build_array('id', v_id)), false) x;
    IF v_now IS NULL THEN
      RETURN authz_int.scim_no(404, NULL, 'no user ' || p_id);
    ELSIF p_method = 'GET' THEN
      RETURN ROW(200, v_now, NULL)::authz_int.scim_answer;
    END IF;
  END IF;
  IF v_function IS NULL THEN
    RETURN authz_int.scim_no(501, NULL, 'the SCIM settings name no function that makes, changes or deletes a user (authz.set_scim: user_function)');
  ELSIF p_method = 'PATCH' THEN
    SELECT * INTO p FROM authz_int.scim_patch(v_now, p_body->'Operations');
    IF p.why IS NOT NULL THEN
      RETURN authz_int.scim_no(400, p.scim_type, p.why);
    END IF;
    v_new := p.resource;
  ELSIF p_method <> 'DELETE' THEN
    v_new := CASE WHEN jsonb_typeof(p_body) = 'object' THEN p_body ELSE '{}' END;
  END IF;
  IF p_method <> 'DELETE' THEN
    v_new := v_new - 'password';
    IF jsonb_typeof(v_new->'active') = 'string' AND lower(v_new->>'active') IN ('true', 'false') THEN   -- ("False": what Entra ID sends unless its flag for SCIM's own form is set)
      v_new := v_new || jsonb_build_object('active', lower(v_new->>'active') = 'true');
    END IF;
    IF jsonb_typeof(v_new->'userName') IS DISTINCT FROM 'string' OR v_new->>'userName' = '' THEN
      RETURN authz_int.scim_no(400, 'invalidValue', 'userName: a user has one, a text that isn''t empty');
    ELSIF jsonb_typeof(v_new->'active') NOT IN ('boolean', 'null') THEN
      RETURN authz_int.scim_no(400, 'invalidValue', 'active: true or false');
    END IF;
    SELECT * INTO g FROM authz_int.scim_rows(p_settings, 'user', jsonb_build_array(jsonb_build_array('username', v_new->>'userName')), false);
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(g.resources) x(other) WHERE x.other->>'id' IS DISTINCT FROM v_id) THEN
      RETURN authz_int.scim_no(409, 'uniqueness', format('a user has the userName %s already', v_new->>'userName'));
    END IF;
  END IF;
  SELECT * INTO c FROM authz_int.scim_call(v_function, 'user', v_id, v_new);
  IF (c.refusal).status IS NOT NULL THEN
    RETURN c.refusal;
  ELSIF p_method = 'DELETE' THEN
    RETURN ROW(204, NULL, NULL)::authz_int.scim_answer;
  END IF;
  SELECT x.resources->0 INTO v_now FROM authz_int.scim_rows(p_settings, 'user', jsonb_build_array(jsonb_build_array('id', c.key)), false) x;
  RETURN ROW(CASE p_method WHEN 'POST' THEN 201 ELSE 200 END, v_now, CASE p_method WHEN 'POST' THEN 'Users/' || c.key END)::authz_int.scim_answer;
END $f$;

-- An identity provider's SCIM request answered (RFC 7644): what a route got, in; what it answers, out.
--   SELECT status, body, location FROM authz.scim('PATCH', 'Groups/10', '', '{"Operations": [...]}', 'ak_...')
-- p_path: the path below the route, as the route read it (Groups/10); p_query: the query string as it was sent
-- (filter=displayName%20eq%20%22Engineering%22); p_token: the bearer token. location: for what was made (201), its
-- path below the route.
-- A request is the provider's when its token is an API key of the principal the settings name (authz.set_scim), and
-- its transaction is then signed in as that principal, as authz.login_key signs it in: the audit trail says who.
-- Nothing else says who asks: the app role may call this, and gets 401 without that key. A key limited to scopes
-- that write nothing reads, and changes nothing (403).
CREATE FUNCTION authz.scim(p_method text, p_path text, p_query text, p_body jsonb, p_token text,
  OUT status int, OUT body jsonb, OUT location text)
LANGUAGE plpgsql {DEF} AS $f$
DECLARE v_settings jsonb; k authz.api_keys; v_answer authz_int.scim_answer; v_method text := upper(coalesce(p_method, ''));
        v_path text := btrim(coalesce(p_path, ''), '/'); v_parts text[]; v_query jsonb;
BEGIN
  SELECT coalesce(jsonb_object_agg(substr(x.key, 6), x.value), '{}') INTO v_settings
  FROM authz.settings x WHERE starts_with(x.key, 'scim_');
  -- the key's principal is read before anyone is signed in: a key that is someone else's signs nobody in
  SELECT * INTO k FROM authz.api_keys x WHERE x.hash = encode(sha256(convert_to(coalesce(p_token, ''), 'UTF8')), 'hex');
  IF k.id IS NOT NULL AND (k.principal_type || ':' || k.user_id) IS NOT DISTINCT FROM (v_settings->>'principal') THEN
    BEGIN
      PERFORM authz.login_key(p_token);
    EXCEPTION WHEN invalid_authorization_specification THEN   -- revoked, expired, its principal gone, someone signed in
      k.id := NULL;
    END;
  ELSE
    k.id := NULL;
  END IF;
  v_parts := string_to_array(v_path, '/');
  IF k.id IS NULL THEN
    v_answer := authz_int.scim_no(401, NULL, 'the bearer token is not an API key of the principal the SCIM settings name');
  ELSIF v_method <> 'GET' AND NOT authz_int.writable() THEN
    v_answer := authz_int.scim_no(403, NULL, 'this key is read-only: it reads users and groups, and changes none');
  ELSE
    v_query := authz_int.scim_query(p_query);
    IF v_query IS NULL THEN
      v_answer := authz_int.scim_no(400, 'invalidSyntax', 'the query string''s escapes are no text');
    ELSIF v_parts[1] = 'Groups' AND cardinality(v_parts) <= 2 THEN
      v_answer := authz_int.scim_group(v_settings, v_method, v_parts[2], v_query, p_body);
    ELSIF v_parts[1] = 'Users' AND cardinality(v_parts) <= 2 THEN
      v_answer := authz_int.scim_user(v_settings, v_method, v_parts[2], v_query, p_body);
    ELSE
      v_answer := authz_int.scim_no(404, NULL, 'nothing is served at ' || v_path);
    END IF;
  END IF;
  status := v_answer.status; body := v_answer.body; location := v_answer.location;
END $f$;

-- Name what the SCIM endpoint reads: the settings as one JSON object, which replaces the stored ones (an empty one
-- turns the endpoint off). For the tables' owner: the principal named here writes users and groups.
--   SELECT authz.set_scim('{"principal": "service:7", "group": "team.member", "group_name": "name"}')
-- principal (type:id): whose API key signs the provider in. group (type.relation): the groups, a relation
-- authz.sync_members takes; group_name, group_external_id: the columns of its table that hold a group's displayName
-- and externalId; group_function: the app's function that makes, changes and deletes a group. user_name,
-- user_external_id, user_function: the same for the users' table; user_active: its column that says whether a
-- user is active (without one, every user is); user_resource: its jsonb column where the app's function keeps a
-- user as the provider wrote it (without one, a user is what the other columns say). page: the most a list
-- answers (100). A function is (p_id text, p_resource jsonb) RETURNS text: p_id NULL makes the row, p_resource NULL deletes
-- it, and it answers the row's key; it runs as the owner, so it is the owner's own. Each setting is checked now, so
-- that a mistake is found here and not at the provider's first request
CREATE FUNCTION authz.set_scim(p_settings jsonb) RETURNS void
LANGUAGE plpgsql {DEF} AS $f$
DECLARE v_names text[] := {NAMES}; v_set jsonb := '{}'; s record; v_type text; v_id text; v_name text; v_table text;
        v_column_type text; v_function text;
BEGIN
  IF p_settings IS NULL OR jsonb_typeof(p_settings) <> 'object' THEN
    RAISE EXCEPTION 'say the SCIM settings as a JSON object (an empty one turns the endpoint off)'
      USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
  END IF;
  FOR s IN SELECT x.key AS name, jsonb_typeof(x.value) AS kind, x.value #>> '{}' AS said FROM jsonb_each(p_settings) x ORDER BY x.key LOOP
    IF s.name <> ALL (v_names) THEN
      RAISE EXCEPTION '% is no SCIM setting (they are: %)', s.name, array_to_string(v_names, ', ')
        USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
    ELSIF s.kind NOT IN ('string', 'number', 'null') THEN
      RAISE EXCEPTION '%: write the setting as a text', s.name USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
    ELSIF s.kind <> 'null' THEN
      v_set := v_set || jsonb_build_object(s.name, s.said);
    END IF;
  END LOOP;
  IF v_set <> '{}' THEN
    v_type := split_part(v_set->>'principal', ':', 1);
    v_id := substr(v_set->>'principal', length(v_type) + 2);
    IF coalesce(v_type, '') = '' OR v_id = '' THEN
      RAISE EXCEPTION 'principal: name whose API key signs the provider in, as type:id (service:7)'
        USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
    ELSIF v_type <> 'user' AND NOT EXISTS (SELECT 1 FROM authz_int.types x WHERE x.name = v_type AND x.principal) THEN
      RAISE EXCEPTION 'principal %: no type % that signs in (user, or a type ... principal)', v_set->>'principal', v_type
        USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
    ELSIF NOT authz_int.hold(v_type, authz_int.canon(v_type, v_id)) THEN
      RAISE EXCEPTION 'principal %: there is no % %', v_set->>'principal', v_type, v_id
        USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
    END IF;
    v_set := v_set || jsonb_build_object('principal', v_type || ':' || authz_int.canon(v_type, v_id));
    IF v_set ? 'group' AND NOT authz_int.takes_members(v_set->>'group') THEN
      RAISE EXCEPTION 'group %: no relation with one table of members (it needs one source: table(group -> user), without where), as authz.sync_members takes',
        v_set->>'group' USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
    END IF;
    FOREACH v_name IN ARRAY ARRAY['group_name', 'group_external_id', 'group_function', 'user_name', 'user_external_id', 'user_active', 'user_resource'] LOOP
      SELECT to_regclass(x.tbl)::text INTO v_table FROM authz_int.types x
      WHERE x.name = CASE WHEN v_name LIKE 'group%' THEN split_part(v_set->>'group', '.', 1) ELSE 'user' END;
      IF v_set ? v_name AND v_table IS NULL THEN
        RAISE EXCEPTION '% is a setting of the group: name it (group, as type.relation)', v_name
          USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
      ELSIF v_name = 'group_name' AND v_set ? 'group' AND NOT v_set ? v_name THEN
        RAISE EXCEPTION 'group_name: name the column of % that holds a group''s displayName', v_table
          USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
      END IF;
      CONTINUE WHEN NOT v_set ? v_name OR v_name = 'group_function';
      SELECT format_type(a.atttypid, a.atttypmod) INTO v_column_type FROM pg_attribute a
      WHERE a.attrelid = to_regclass(v_table) AND a.attname = v_set->>v_name AND a.attnum > 0 AND NOT a.attisdropped;
      IF v_column_type IS NULL THEN
        RAISE EXCEPTION '%: % has no column %', v_name, v_table, v_set->>v_name
          USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
      ELSIF v_column_type <> (CASE v_name WHEN 'user_active' THEN 'boolean' WHEN 'user_resource' THEN 'jsonb' ELSE v_column_type END) THEN
        RAISE EXCEPTION '%: %.% is %, and the setting names a % column', v_name, v_table, v_set->>v_name, v_column_type,
            CASE v_name WHEN 'user_active' THEN 'boolean' ELSE 'jsonb' END
          USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
      END IF;
    END LOOP;
    -- a function of the app's is called as the owner: it is one the owner (or a role that is the owner's, or a
    -- superuser) owns, found by its schema and name, never through a search path
    FOREACH v_name IN ARRAY ARRAY['group_function', 'user_function'] LOOP
      CONTINUE WHEN NOT v_set ? v_name;
      SELECT format('%I.%I', n.nspname, p.proname) INTO v_function
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles r ON r.oid = p.proowner, pg_namespace o
      WHERE p.oid = to_regprocedure((v_set->>v_name) || '(text, jsonb)') AND p.prokind = 'f' AND NOT p.proretset
        AND p.prorettype = 'text'::regtype AND o.nspname = 'authz_int' AND (r.rolsuper OR pg_has_role(p.proowner, o.nspowner, 'MEMBER'));
      IF v_function IS NULL THEN
        RAISE EXCEPTION '%: % is no function (text, jsonb) that returns text and belongs to the policy''s owner (write it with its schema)',
          v_name, v_set->>v_name USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
      END IF;
      v_set := v_set || jsonb_build_object(v_name, v_function);
    END LOOP;
    IF v_set ? 'page' AND NOT (CASE WHEN v_set->>'page' ~ '^[0-9]{1,4}$' THEN (v_set->>'page')::int BETWEEN 1 AND 1000 ELSE false END) THEN
      RAISE EXCEPTION 'page: a whole number from 1 to 1000 (the most a list answers; 100 when it isn''t set)'
        USING ERRCODE = 'invalid_parameter_value', HINT = 'rowstile help AZ720';
    END IF;
  END IF;
  DELETE FROM authz.settings x WHERE starts_with(x.key, 'scim_');
  INSERT INTO authz.settings (key, value) SELECT 'scim_' || x.key, x.value FROM jsonb_each_text(v_set) x;
  PERFORM authz_int.audit('set_scim', NULL, NULL, NULL, NULL, NULL, NULL, v_set);
END $f$;"""


class ScimMixin(IdentityMixin):
    def scim_sql(self) -> str:
        """The endpoint's functions. Of the policy they hold the relations authz.sync_members takes alone (which
        may be the groups, and where their members are read): the rest is read from the settings and from
        authz_int.types when a request is answered, so settings made before a policy changed are found wanting
        then, not here."""
        reads = []
        for t, r, src in self.member_tables():
            this = (
                self.key_is(t, "s", "$2", src.obj_col)
                if t.composite
                else f"s.{q(cols(src.obj_col)[0])} = $2::{t.pktype}"
            )
            member = f"s.{q(cols(self.source_columns(src))[0])}"
            reads.append(
                f"    WHEN {lit(t.name + '.' + r.name)} THEN\n"
                f"      RETURN ARRAY(SELECT {member}::text FROM {qt(src.table)} s WHERE {this} ORDER BY {member});"
            )
        # (a simple CASE, whose branches may come in any order: the types' order in the policy changes no function)
        body = "  CASE $1\n" + "\n".join(reads) + "\n  END CASE;" if reads else "  RETURN NULL;"
        names = ", ".join(lit(t.name + "." + r.name) for t, r, _ in self.member_tables())
        members = f"""-- the relations authz.sync_members takes: read from one table of members (group -> user), without where
CREATE FUNCTION authz_int.takes_members(p_relation text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $f$
  SELECT coalesce(p_relation = ANY (ARRAY[{names}]::text[]), false) $f$;
-- a group's members in that table, as ids, in the order of the users' keys (p_relation: type.relation)
CREATE FUNCTION authz_int.members_of(p_relation text, p_id text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
{body}
END $f$;"""
        return (
            members
            + "\n\n"
            + SCIM_SQL.replace("{DEF}", DEF).replace("{NAMES}", "ARRAY[" + ", ".join(lit(n) for n in SETTINGS) + "]")
        )
