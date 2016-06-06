/*-------------------------------------------------------------------------
 *
 * pg_log_authfail.c
 *		Report all failed connection attemps.
 *
 *
 * Copyright (c) 2013, Julien Rouhaud (Dalibo),
 * julien.rouhaud@dalibo.com
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <syslog.h>

#include "utils/guc.h"
#include "libpq/auth.h"   /* For ClientAuthentication hook	*/
#include "libpq/libpq-be.h" /* For Port						*/
#include "miscadmin.h"

PG_MODULE_MAGIC;

#ifndef PG_SYSLOG_LIMIT
#define PG_SYSLOG_LIMIT 1024
#endif

/*---- Local variables ----*/
static const struct config_enum_entry log_destination_options[] = {
	{"stderr", 1, false},
	{"syslog", 2, false},
	{NULL, 0}
};

static const struct config_enum_entry syslog_facility_options[] = {
	{"local0", LOG_LOCAL0, false},
	{"local1", LOG_LOCAL1, false},
	{"local2", LOG_LOCAL2, false},
	{"local3", LOG_LOCAL3, false},
	{"local4", LOG_LOCAL4, false},
	{"local5", LOG_LOCAL5, false},
	{"local6", LOG_LOCAL6, false},
	{"local7", LOG_LOCAL7, false},
	{NULL, 0}
};


static bool    openlog_done = false;
static char *  syslog_ident = NULL;
static int     log_destination = 1; /* aka stderr */
static int     syslog_facility = LOG_LOCAL0;

/* Saved hook values in case of unload */
static ClientAuthentication_hook_type prev_ClientAuthentication = NULL;

/*---- Function declarations ----*/

void		_PG_init(void);
void		_PG_fini(void);

static void pglaf_ClientAuthentication(Port *port, int status);
static void pglaf_log(const Port *port);
static void write_syslog(int level, char *line);

extern int pg_mbcliplen(const char *mbstr, int len, int limit);

/*
 * Module load callback
 */
void
_PG_init(void)
{
	/*
	 * In order to create our shared memory area, we have to be loaded via
	 * shared_preload_libraries.  If not, fall out without hooking into any of
	 * the main system.  (We don't throw error here because it seems useful to
	 * allow the pglaf_log functions to be created even when the module
	 * isn't active.  The functions must protect themselves against
	 * being called then, however.)
	 */
	if (!process_shared_preload_libraries_in_progress)
		return;

	/*
	 * Define (or redefine) custom GUC variables.
	 */
	DefineCustomEnumVariable( "pg_log_authfail.log_destination",
				"Selects log destination (either stderr or syslog).",
				NULL,
				&log_destination,
				log_destination,
				log_destination_options,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL);
	DefineCustomEnumVariable( "pg_log_authfail.syslog_facility",
				"Selects syslog level of log (same options than PostgreSQL syslog_facility).",
				NULL,
				&syslog_facility,
				syslog_facility,
				syslog_facility_options,
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL);
	DefineCustomStringVariable( "pg_log_authfail.syslog_ident",
				"Select syslog program identity name.",
				NULL,
				&syslog_ident,
				"pg_log_authfail",
				PGC_POSTMASTER,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );

	if (log_destination == 2 /* aka syslog */)
	{
		/* Open syslog descriptor */
		openlog(syslog_ident, LOG_PID | LOG_NDELAY | LOG_NOWAIT, syslog_facility);
		openlog_done = true;
	}

	/*
	 * Install hooks.
	 */
	prev_ClientAuthentication = ClientAuthentication_hook;
	ClientAuthentication_hook = pglaf_ClientAuthentication;
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Close syslog descriptor, if required */
	if (openlog_done)
	{
		closelog();
		openlog_done = false;
	}

	/* Uninstall hooks. */
	ClientAuthentication_hook = prev_ClientAuthentication;
}

/*
 * ClientAuthentication hook: log all failed attemps
 */
static void
pglaf_ClientAuthentication(Port *port, int status)
{
	if ( status == STATUS_ERROR )
	{
		pglaf_log(port);
	}
	if (prev_ClientAuthentication)
		prev_ClientAuthentication(port, status);
}

/*
 * Log failed attemps.
 */
static void
pglaf_log(const Port *port)
{
	char *tmp_authmsg = NULL;
	char *localport;

#if PG_VERSION_NUM >= 90600
	localport = GetConfigOptionByName("port", NULL, false);
#else
	localport = GetConfigOptionByName("port", NULL);
#endif

	Assert(port != NULL);

	/* Allocate the new string */
	tmp_authmsg = palloc(60);

	if (tmp_authmsg == NULL)
		return;
	/* not sure why this is needed */
	tmp_authmsg[0] = '\0';

	sprintf(tmp_authmsg, "Failed authentication from %s on port %s", port->remote_host, localport);

	if (tmp_authmsg != NULL)
	{
		/*
		 * Write a message line to syslog or elog
		 * depending on the fact that we opened syslog at the beginning
		 */
		if (openlog_done)
			write_syslog(LOG_ERR, tmp_authmsg);
		else
			elog(LOG, "%s", tmp_authmsg);

		/* Free the log string */
		pfree(tmp_authmsg);
	}
}

/*
 * Write a message line to syslog
 */
static void
write_syslog(int level, char *line)
{
	static unsigned long seq = 0;
	int len;
	const char *nlpos;

	/*
	 * We add a sequence number to each log message to suppress "same"
	 * messages.
	 */
	seq++;

	/*
	 * Our problem here is that many syslog implementations don't handle long
	 * messages in an acceptable manner. While this function doesn't help that
	 * fact, it does work around by splitting up messages into smaller pieces.
	 *
	 * We divide into multiple syslog() calls if message is too long or if the
	 * message contains embedded newline(s).
	 */
	len = strlen(line);
	nlpos = strchr(line, '\n');
	if (len > PG_SYSLOG_LIMIT || nlpos != NULL)
	{
		int chunk_nr = 0;
		while (len > 0)
		{
			char buf[PG_SYSLOG_LIMIT + 1];
			int  buflen;
			int  i;

			/* if we start at a newline, move ahead one char */
			if (line[0] == '\n')
			{
				 line++;
				 len--;
				 /* we need to recompute the next newline's position, too */
				 nlpos = strchr(line, '\n');
				 continue;
			}

			/* copy one line, or as much as will fit, to buf */
			if (nlpos != NULL)
				buflen = nlpos - line;
			else
				buflen = len;
			buflen = Min(buflen, PG_SYSLOG_LIMIT);
			memcpy(buf, line, buflen);
			buf[buflen] = '\0';

			/* trim to multibyte letter boundary */
			buflen = pg_mbcliplen(buf, buflen, buflen);
			if (buflen <= 0)
				return;
			buf[buflen] = '\0';

			/* already word boundary? */
			if (line[buflen] != '\0' &&
				!isspace((unsigned char) line[buflen]))
			{
				/* try to divide at word boundary */
				i = buflen - 1;
				while (i > 0 && !isspace((unsigned char) buf[i]))
					i--;

				/* else couldn't divide word boundary */
				if (i > 0)
				{
					buflen = i;
					buf[i] = '\0';
				}
			}

			chunk_nr++;

			syslog(level, "[%lu-%d] %s", seq, chunk_nr, buf);
			line += buflen;
			len -= buflen;
		}
	}
	else
	{
		/* message short enough */
		syslog(level, "[%lu] %s", seq, line);
	}
}
