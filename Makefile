MODULE_big = pg_log_authfail
OBJS = pg_log_authfail.o

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
