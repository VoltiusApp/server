-- Canonicalize stored email addresses to lower case.
--
-- `users.email` was stored exactly as typed while every client-side lookup and
-- `invite_member` already lowercased their input. A mixed-case row was therefore
-- unreachable: /v1/auth/challenge returned 404 for the account's own owner, and a
-- team invite to the same mailbox missed the existing user and fell through to a
-- pending invitation.
--
-- Both tables are verified collision-free before the unique index goes on.

UPDATE users SET email = lower(btrim(email)) WHERE email <> lower(btrim(email));

UPDATE pending_invitations
   SET email = lower(btrim(email))
 WHERE email <> lower(btrim(email));

-- Enforce the invariant in the database rather than by convention, so a future
-- write path that forgets `email::normalize` fails loudly instead of creating a
-- second row for the same mailbox.
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));
