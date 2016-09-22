pg_log_authfail
===============


pg_log_authfail is a PostgreSQL module that logs each failed connection attempt
in a fixed format and in a potentially specific file.

**It requires PostgreSQL 9.1 or above.**

The output format looks like :

    Failed authentication from X.X.X.X on port Y

Preceded or not by the log_line_prefix format.

The main goal of this tool is to handle those logs with an external tool such
as fail2ban or Splunk, without performance issue.


Installation
============

- Compatible with PostgreSQL 9.1 and above
- Needs PostgreSQL header files
- decompress the tarball
- sudo make install

Configuration
=============

Here are some configuration examples in order to configure PostgreSQL and
fail2ban.

Syslog destination is used in order to redirect logs in a separate logfile,
for performance issue and to keep as much liberty as possible in regular
PostgreSQL logs.

If multiple clusters are located on the server, the same output file can be
used, as the port is specified. Depending on fail2ban configuration, each
cluster can be blocked separately or all at the same time.

**postgresql.conf**
-------------------

    shared_preload_library = 'pg_log_authfail'
    pg_log_authfail.log_destination = syslog
    pg_log_authfail.syslog_ident = pgsql
    pg_log_authfail.use_log_line_prefix = false
    pg_log_authfail.all_authent = false


**syslog.conf**
---------------

    if $programname == 'pgsql' then        -/var/log/postgresql/pg_authfail.log


**fail2ban/jail.conf**
----------------------

    ...
    [pgsql]

    enabled  = true
    port     = 5432
    filter   = postgresql
    logpath  = /var/log/postgresql/pg_authfail.log
    maxretry = 5

NOTE: If you want to block all instances at the same time, you have to specify
every ports on the **port** parameter, comma separated, ie. port = 5432,5433...

NOTE: If you don't specify the **sslmode** on your connection string, your
client should fail twice (with and without ssl) if the PostgreSQL server is
configured to use ssl. Therefore, two failed attempts will be logged.


The included example/pg.conf file show a simple filter for pg_log_authfail
output. It should be copied in the /etc/fail2ban.conf/filter.d directory.


NOTE: if you want to manage each PostgreSQL cluster separately, you have to:

  - duplicate and rename this file for each cluster
  - specify the port in the regexp, as indicated in the example file
  - duplicate entries in the jail.conf file, with a different name (ie.
    [pgsql5434]) matching the duplicate pg.conf file for filter.

Finally, reload your fail2ban daemon and you're done.
