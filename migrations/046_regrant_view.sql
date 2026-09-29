UPDATE team_roles SET permissions = permissions | (1::bigint << 17)
 WHERE team_id NOT IN (SELECT team_id FROM team_rule_sets);
