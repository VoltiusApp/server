UPDATE team_roles SET permissions = permissions | (1::bigint << 17);
