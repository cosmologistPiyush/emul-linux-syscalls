ttIsql -connStr "DSN=ldap_tt;Overwrite=1" -f backsql_create.sql
ttIsql -connStr "DSN=ldap_tt" -f testdb_create.sql
ttIsql -connStr "DSN=ldap_tt" -f testdb_data.sql
ttIsql -connStr "DSN=ldap_tt" -f testdb_metadata.sql
