-- Retire editor and viewer as organization roles.
--
-- The organization roles are owner, admin, member and collaborator
-- (ADR-008). Finer access to one resource is a resource role, not an
-- organization role. Existing memberships and pending invitations map as
-- follows: editor becomes member, viewer becomes collaborator.
--
-- Both mappings reduce what the role grants in the organization, so an
-- access change is recorded for each active membership that changes, and
-- relying parties refuse tokens issued before it. A collaborator keeps no
-- organization-wide view; grant the person a role on the resources they
-- need.
--
-- Run it against an existing database when deploying this version, then
-- re-sync the relationship engine if one is in use (a rebac deployment
-- rewrites organization#editor and organization#viewer relationships as
-- organization#member and organization#collaborator). A fresh database
-- needs nothing. It is safe to run more than once: after the first run no
-- row has a retired role, so nothing changes and no record is written.
-- Postgres syntax; for a SQLite development database, recreate it.

WITH changed AS (
    UPDATE sf_principal_memberships
    SET role = CASE role WHEN 'editor' THEN 'member' ELSE 'collaborator' END
    WHERE role IN ('editor', 'viewer')
    RETURNING principal_id, organization_id, active
)
INSERT INTO sf_access_changes (id, principal_id, organization_id, changed_at, reason)
SELECT gen_random_uuid(), principal_id, organization_id, now(), 'org_role_changed'
FROM changed
WHERE active;

UPDATE sf_invites
SET role = CASE role WHEN 'editor' THEN 'member' ELSE 'collaborator' END
WHERE role IN ('editor', 'viewer');
