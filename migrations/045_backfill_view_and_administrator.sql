UPDATE team_roles SET permissions = permissions | (1::bigint << 17);
UPDATE team_roles SET permissions = permissions | (1::bigint << 18)
 WHERE is_builtin AND name = 'owner';
