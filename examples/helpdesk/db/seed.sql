-- The demo's data, as the tables' owner (test.sh loads it after the migrations). Two
-- workspaces: Acme's desk (an admin, a lead, two agents, teams inside teams, a customer org, an email intake) and
-- Globex's (an admin and a customer), and one of the vendor's staff. Sign in with any of these emails.
INSERT INTO hd.workspaces (id, name) VALUES
  ('a0000000-0000-4000-8000-000000000001', 'Acme'),
  ('b0000000-0000-4000-8000-000000000001', 'Globex');

INSERT INTO hd.customer_orgs (id, workspace_id, name, shared_tickets) VALUES
  ('a0000000-0000-4000-8000-0000000000c1', 'a0000000-0000-4000-8000-000000000001', 'Initech', true);

INSERT INTO hd.users (id, workspace_id, kind, role, customer_org_id, name, email, notes) VALUES
  ('a0000000-0000-4000-8000-000000000a01', 'a0000000-0000-4000-8000-000000000001', 'agent', 'admin', NULL, 'Ann Admin', 'ann@acme.test', NULL),
  ('a0000000-0000-4000-8000-000000000a02', 'a0000000-0000-4000-8000-000000000001', 'agent', 'agent', NULL, 'Lea Lead', 'lea@acme.test', NULL),
  ('a0000000-0000-4000-8000-000000000a03', 'a0000000-0000-4000-8000-000000000001', 'agent', 'agent', NULL, 'Al Billing', 'al@acme.test', NULL),
  ('a0000000-0000-4000-8000-000000000a04', 'a0000000-0000-4000-8000-000000000001', 'agent', 'agent', NULL, 'Oz Hardware', 'oz@acme.test', NULL),
  ('a0000000-0000-4000-8000-000000000c01', 'a0000000-0000-4000-8000-000000000001', 'customer', NULL, 'a0000000-0000-4000-8000-0000000000c1', 'Peter Gibbons', 'peter@initech.test', 'Prefers a call back'),
  ('a0000000-0000-4000-8000-000000000c02', 'a0000000-0000-4000-8000-000000000001', 'customer', NULL, 'a0000000-0000-4000-8000-0000000000c1', 'Milton W.', 'milton@initech.test', NULL),
  ('a0000000-0000-4000-8000-000000000c03', 'a0000000-0000-4000-8000-000000000001', 'customer', NULL, NULL, 'Cy Walker', 'cy@mail.test', NULL),
  ('b0000000-0000-4000-8000-000000000a01', 'b0000000-0000-4000-8000-000000000001', 'agent', 'admin', NULL, 'Bob Globex', 'bob@globex.test', NULL),
  ('b0000000-0000-4000-8000-000000000c01', 'b0000000-0000-4000-8000-000000000001', 'customer', NULL, NULL, 'Xu Li', 'xu@mail.test', NULL),
  ('f0000000-0000-4000-8000-000000000001', NULL, 'staff', NULL, NULL, 'Sam Vendor', 'sam@vendor.test', NULL);

INSERT INTO hd.teams (id, workspace_id, parent_id, name) VALUES
  ('a0000000-0000-4000-8000-0000000000e1', 'a0000000-0000-4000-8000-000000000001', NULL, 'Support'),
  ('a0000000-0000-4000-8000-0000000000e2', 'a0000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-0000000000e1', 'Billing'),
  ('a0000000-0000-4000-8000-0000000000e3', 'a0000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-0000000000e1', 'Hardware');
INSERT INTO hd.team_leads (workspace_id, team_id, user_id) VALUES
  ('a0000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-0000000000e1', 'a0000000-0000-4000-8000-000000000a02');
INSERT INTO hd.team_members (workspace_id, team_id, user_id) VALUES
  ('a0000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-0000000000e2', 'a0000000-0000-4000-8000-000000000a03'),
  ('a0000000-0000-4000-8000-000000000001', 'a0000000-0000-4000-8000-0000000000e3', 'a0000000-0000-4000-8000-000000000a04');

INSERT INTO hd.integrations (id, workspace_id, name) VALUES
  ('a0000000-0000-4000-8000-0000000000f1', 'a0000000-0000-4000-8000-000000000001', 'Email');

INSERT INTO hd.tickets (id, workspace_id, subject, requester_id, team_id, assignee_id) VALUES
  ('a0000000-0000-4000-8000-000000000101', 'a0000000-0000-4000-8000-000000000001', 'Invoice 4410 charged twice', 'a0000000-0000-4000-8000-000000000c01', 'a0000000-0000-4000-8000-0000000000e2', 'a0000000-0000-4000-8000-000000000a03'),
  ('a0000000-0000-4000-8000-000000000102', 'a0000000-0000-4000-8000-000000000001', 'The printer says PC LOAD LETTER', 'a0000000-0000-4000-8000-000000000c02', 'a0000000-0000-4000-8000-0000000000e3', NULL),
  ('a0000000-0000-4000-8000-000000000103', 'a0000000-0000-4000-8000-000000000001', 'Password reset never arrives', 'a0000000-0000-4000-8000-000000000c03', NULL, NULL),
  ('b0000000-0000-4000-8000-000000000101', 'b0000000-0000-4000-8000-000000000001', 'Globex: export to CSV', 'b0000000-0000-4000-8000-000000000c01', NULL, 'b0000000-0000-4000-8000-000000000a01');

INSERT INTO hd.comments (ticket_id, author_id, internal, body) VALUES
  ('a0000000-0000-4000-8000-000000000101', 'a0000000-0000-4000-8000-000000000c01', false, 'I was charged twice for invoice 4410.'),
  ('a0000000-0000-4000-8000-000000000101', 'a0000000-0000-4000-8000-000000000a03', true, 'The payment provider shows two captures: refund one.'),
  ('a0000000-0000-4000-8000-000000000101', 'a0000000-0000-4000-8000-000000000a03', false, 'Sorry about that: one of them is refunded.'),
  ('a0000000-0000-4000-8000-000000000102', 'a0000000-0000-4000-8000-000000000c02', false, 'PC LOAD LETTER. What does that mean?'),
  ('a0000000-0000-4000-8000-000000000103', 'a0000000-0000-4000-8000-000000000c03', false, 'I asked three times.'),
  ('b0000000-0000-4000-8000-000000000101', 'b0000000-0000-4000-8000-000000000c01', false, 'Can we export the report?');

-- how each of them signs in (the demo: by email alone)
INSERT INTO hd.logins (email, user_id) SELECT email, id FROM hd.users;
