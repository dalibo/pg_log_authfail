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
#include "lib/stringinfo.h"
#include "pgtime.h"

PG_MODULE_MAGIC;

#ifndef PG_SYSLOG_LIMIT
#define PG_SYSLOG_LIMIT 1024
#endif

#define FORMATTED_TS_LEN 128

#define PGLAF_STDERR 1
#define PGLAF_SYSLOG 2

/*---- Local variables ----*/
static const struct config_enum_entry log_destination_options[] = {
	{"stderr", PGLAF_STDERR, false},
	{"syslog", PGLAF_SYSLOG, false},
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


static bool		openlog_done = false;
static char	   *syslog_ident = NULL;
static int		log_destination = PGLAF_STDERR;
static int		syslog_facility = LOG_LOCAL0;
static bool		use_log_line_prefix = false; /* Don't prepend log_line_prefix */
static bool		log_success = false; /* Don't log successful attemtps */
static bool		log_abort = false; /* Don't log aborted attemtps */

/* Saved hook values in case of unload */
static ClientAuthentication_hook_type prev_ClientAuthentication = NULL;

/*---- Function declarations ----*/

void		_PG_init(void);
void		_PG_fini(void);

static void assign_pglaf_destination(int newval, void *extra);
static void assign_pglaf_facility(int newval, void *extra);
static void assign_pglaf_ident(const char *newval, void *extra);

static void pglaf_line_prefix(StringInfo buf, Port *port);
static void pglaf_ClientAuthentication(Port *port, int status);
static void pglaf_log(Port *port, const char *prefix);
static void write_syslog(int level, char *line);
static void start_syslog(void);
static void stop_syslog(void);
static void restart_syslog(void);

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
				PGC_SIGHUP,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				assign_pglaf_destination,
				NULL);

	DefineCustomEnumVariable( "pg_log_authfail.syslog_facility",
				"Selects syslog level of log (same options than PostgreSQL syslog_facility).",
				NULL,
				&syslog_facility,
				syslog_facility,
				syslog_facility_options,
				PGC_SIGHUP,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				assign_pglaf_facility,
				NULL);

	DefineCustomStringVariable( "pg_log_authfail.syslog_ident",
				"Select syslog program identity name.",
				NULL,
				&syslog_ident,
				"pg_log_authfail",
				PGC_SIGHUP,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				assign_pglaf_ident,
				NULL );

	DefineCustomBoolVariable( "pg_log_authfail.use_log_line_prefix",
				"Prefix log line as standart log output using pg_log_line_prefix.",
				NULL,
				&use_log_line_prefix,
				use_log_line_prefix,
				PGC_SIGHUP,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );

	DefineCustomBoolVariable( "pg_log_authfail.log_success",
				"If true, also trace successful connection attempts.",
				NULL,
				&log_success,
				log_success,
				PGC_SIGHUP,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );

	DefineCustomBoolVariable( "pg_log_authfail.log_abort",
				"If true, also trace aborted (eof) connection attempts.",
				NULL,
				&log_abort,
				log_abort,
				PGC_SIGHUP,
				0,
#if PG_VERSION_NUM >= 90100
				NULL,
#endif
				NULL,
				NULL );

#ifdef HAVE_SYSLOG
	if (log_destination == PGLAF_SYSLOG)
		/* Open syslog descriptor */
		start_syslog();
#endif

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
	stop_syslog();

	/* Uninstall hooks. */
	ClientAuthentication_hook = prev_ClientAuthentication;
}

/*
 * Assign hook for syslog descriptor, destination changed. Open or close syslog
 * as needed.
 */
static void
assign_pglaf_destination(int newval, void *extra)
{
#ifdef HAVE_SYSLOG
	if (newval == PGLAF_SYSLOG && log_destination != PGLAF_SYSLOG)
		/* switching to syslog */
		start_syslog();
	else if (newval != PGLAF_SYSLOG && log_destination == PGLAF_SYSLOG)
		/* switching from syslog to stderr */
		stop_syslog();
#endif
	/* without syslog support, just ignore it */
}

/*
 * Assign hook for syslog descriptor, facility changed. Restart syslog if needed
 */
static void
assign_pglaf_facility(int newval, void *extra)
{
#ifdef HAVE_SYSLOG
	syslog_facility = newval;

	if (log_destination == PGLAF_SYSLOG)
		restart_syslog();
#endif
	/* without syslog support, just ignore it */
}

/*
 * Assign hook for syslog descriptor, ident changed. Restart syslog if needed
 */
static void
assign_pglaf_ident(const char *newval, void *extra)
{
#ifdef HAVE_SYSLOG
	syslog_ident = (char *) newval;

	if (log_destination == PGLAF_SYSLOG)
		restart_syslog();
#endif
	/* without syslog support, just ignore it */
}

/*-------------------------------
 * Format tag info for log lines; append to the provided buffer.
 * Copied from log_line_prefix() in elog.c
 */
static void
pglaf_line_prefix(StringInfo buf, Port *port)
{
	/* static counter for line numbers */
	static long	log_line_number = 0;

	/* has counter been reset in current process? */
	static int	log_my_pid = 0;
	int		padding;
	const char 	*p;

	/*
	 * This is one of the few places where we'd rather not inherit a static
	 * variable's value from the postmaster.  But since we will, reset it when
	 * MyProcPid changes. MyStartTime also changes when MyProcPid does, so
	 * reset the formatted start timestamp too.
	 */
	if (log_my_pid != MyProcPid)
	{
		log_line_number = 0;
		log_my_pid = MyProcPid;
	}
	log_line_number++;

	if (Log_line_prefix == NULL)
		return;					/* in case guc hasn't run yet */

	for (p = Log_line_prefix; *p != '\0'; p++)
	{
		if (*p != '%')
		{
			/* literal char, just copy */
			appendStringInfoChar(buf, *p);
			continue;
		}

		/* must be a '%', so skip to the next char */
		p++;
		if (*p == '\0')
			break;				/* format error - ignore it */
		else if (*p == '%')
		{
			/* string contains %% */
			appendStringInfoChar(buf, '%');
			continue;
		}


		/*
		 * Process any formatting which may exist after the '%'.
		 *
		 * Note: Since only '-', '0' to '9' are valid formatting characters we
		 * can do a quick check here to pre-check for formatting. If the char
		 * is not formatting then we can skip a useless function call.
		 *
		 * Further note: At least on some platforms, passing %*s rather than
		 * %s to appendStringInfo() is substantially slower, so many of the
		 * cases below avoid doing that unless non-zero padding is in fact
		 * specified.
		 */
		if (*p > '9')
			padding = 0;

		/* process the option */
		switch (*p)
		{
			case 'a':
				if (port)
				{
					const char *appname = application_name;

					if (appname == NULL || *appname == '\0')
						appname = _("[unknown]");
					if (padding != 0)
						appendStringInfo(buf, "%*s", padding, appname);
					else
						appendStringInfoString(buf, appname);
				}
				else if (padding != 0)
					appendStringInfoSpaces(buf,
										   padding > 0 ? padding : -padding);

				break;
			case 'u':
				if (port)
				{
					const char *username = port->user_name;

					if (username == NULL || *username == '\0')
						username = _("[unknown]");
					if (padding != 0)
						appendStringInfo(buf, "%*s", padding, username);
					else
						appendStringInfoString(buf, username);
				}
				else if (padding != 0)
					appendStringInfoSpaces(buf,
										   padding > 0 ? padding : -padding);
				break;
			case 'd':
				if (port)
				{
					const char *dbname = port->database_name;

					if (dbname == NULL || *dbname == '\0')
						dbname = _("[unknown]");
					if (padding != 0)
						appendStringInfo(buf, "%*s", padding, dbname);
					else
						appendStringInfoString(buf, dbname);
				}
				else if (padding != 0)
					appendStringInfoSpaces(buf,
										   padding > 0 ? padding : -padding);
				break;
			case 'c':
				if (padding != 0)
				{
					char strfbuf[128];

					snprintf(strfbuf, sizeof(strfbuf) - 1, "%lx.%x",
						(long) (MyStartTime), MyProcPid);
					appendStringInfo(buf, "%*s", padding, strfbuf);
				}
				else
					appendStringInfo(buf, "%lx.%x", (long) (MyStartTime), MyProcPid);
				break;
			case 'p':
				if (padding != 0)
					appendStringInfo(buf, "%*d", padding, MyProcPid);
				else
					appendStringInfo(buf, "%d", MyProcPid);
				break;
			case 'l':
				if (padding != 0)
					appendStringInfo(buf, "%*ld", padding, log_line_number);
				else
					appendStringInfo(buf, "%ld", log_line_number);
				break;
			case 'm':
				{
					pg_time_t	stamp_time;
					char		msbuf[8];
					char		formatted_log_time[256];
					struct timeval	stamp_timeval;

					gettimeofday(&stamp_timeval, NULL);
					stamp_time = (pg_time_t) stamp_timeval.tv_sec;
					pg_strftime(formatted_log_time, FORMATTED_TS_LEN,
						/* leave room for milliseconds... */
						"%Y-%m-%d %H:%M:%S     %Z",
						pg_localtime(&stamp_time, log_timezone));
					/* 'paste' milliseconds into place... */
					sprintf(msbuf, ".%03d", (int) (stamp_timeval.tv_usec / 1000));
					memcpy(formatted_log_time + 19, msbuf, 4);
					if (padding != 0)
						appendStringInfo(buf, "%*s", padding, formatted_log_time);
					else
						appendStringInfoString(buf, formatted_log_time);
				}
				break;
			case 't':
				{
					pg_time_t	stamp_time = (pg_time_t) time(NULL);
					char		strfbuf[128];

					pg_strftime(strfbuf, sizeof(strfbuf),
							"%Y-%m-%d %H:%M:%S %Z",
							pg_localtime(&stamp_time, log_timezone));
					if (padding != 0)
						appendStringInfo(buf, "%*s", padding, strfbuf);
					else
						appendStringInfoString(buf, strfbuf);
				}
				break;
			case 'n':
				{
					char	strfbuf[128];
					struct timeval  stamp_timeval;

					gettimeofday(&stamp_timeval, NULL);

					sprintf(strfbuf, "%ld.%03d", stamp_timeval.tv_sec,
							(int)(stamp_timeval.tv_usec / 1000));

					if (padding != 0)
						appendStringInfo(buf, "%*s", padding, strfbuf);
					else
						appendStringInfoString(buf, strfbuf);
				}
				break;
			case 's':
				{
					char strfbuf[128];
					/* struct timeval  stamp_timeval; */
					pg_time_t   stamp_time = (pg_time_t) MyStartTime;

					/*
					 * Note: we expect that guc.c will ensure that log_timezone is set up (at
					 * least with a minimal GMT value) before Log_line_prefix can become
					 * nonempty or CSV mode can be selected.
					 */
					pg_strftime(strfbuf, FORMATTED_TS_LEN,
							"%Y-%m-%d %H:%M:%S %Z",
							pg_localtime(&stamp_time, log_timezone));

					/* gettimeofday(&stamp_timeval, NULL); */
					if (padding != 0)
						appendStringInfo(buf, "%*s", padding, strfbuf);
					else
						appendStringInfoString(buf, strfbuf);
				}
				break;
			case 'i':
				if (padding != 0)
					appendStringInfoSpaces(buf,
						padding > 0 ? padding : -padding);
				break;
			case 'r':
				if (port && port->remote_host)
				{
					if (padding != 0)
					{
						if (port->remote_port && port->remote_port[0] != '\0')
						{
							/*
							 * This option is slightly special as the port
							 * number may be appended onto the end. Here we
							 * need to build 1 string which contains the
							 * remote_host and optionally the remote_port (if
							 * set) so we can properly align the string.
							 */

							char	   hostport[64];

							sprintf(hostport, "%s(%s)", port->remote_host, port->remote_port);
							appendStringInfo(buf, "%*s", padding, hostport);
						}
						else
							appendStringInfo(buf, "%*s", padding, port->remote_host);
					}
					else
					{
						/* padding is 0, so we don't need a temp buffer */
						appendStringInfoString(buf, port->remote_host);
						if (port->remote_port &&
							port->remote_port[0] != '\0')
							appendStringInfo(buf, "(%s)",
											 port->remote_port);
					}

				}
				else if (padding != 0)
					appendStringInfoSpaces(buf,
										   padding > 0 ? padding : -padding);
				break;
			case 'h':
				if (port && port->remote_host)
				{
					if (padding != 0)
						appendStringInfo(buf, "%*s", padding, port->remote_host);
					else
						appendStringInfoString(buf, port->remote_host);
				}
				else if (padding != 0)
					appendStringInfoSpaces(buf,
										   padding > 0 ? padding : -padding);
				break;
			case 'q':
				/* in postmaster and friends, stop if %q is seen */
				/* in a backend, just ignore */
				if (port == NULL)
					return;
				break;
			case 'v':
				if (padding != 0)
					appendStringInfoSpaces(buf,
						padding > 0 ? padding : -padding);
				break;
			case 'x':
				if (padding != 0)
					appendStringInfoSpaces(buf,
							padding > 0 ? padding : -padding);
				break;
			case 'e':
				if (padding != 0)
					appendStringInfoSpaces(buf,
							padding > 0 ? padding : -padding);
				break;
			default:
				/* format error - ignore it */
				break;
		}
	}
}
/*
 * ClientAuthentication hook: log all failed attemps
 */
static void
pglaf_ClientAuthentication(Port *port, int status)
{
	switch (status)
	{
		case STATUS_OK:
			if (log_success)
				pglaf_log(port, "Successful");
			break;

		case STATUS_ERROR:
				pglaf_log(port, "Failed");
			break;

		case STATUS_EOF:
			if (log_abort)
				pglaf_log(port, "Aborted");
			break;

		default:
				pglaf_log(port, "UNKNOWN");
			break;
	}

	if (prev_ClientAuthentication)
		prev_ClientAuthentication(port, status);
}

/*
 * Log failed attemps.
 */
static void
pglaf_log(Port *port, const char *prefix)
{
	char *localport=NULL;
	StringInfoData tmp_authmsg;

	Assert(port != NULL);

#if PG_VERSION_NUM >= 90600
	localport = GetConfigOptionByName("port", NULL, false);
#else
	localport = GetConfigOptionByName("port", NULL);
#endif

	initStringInfo(&tmp_authmsg);

	if (use_log_line_prefix == true )
	{
		pglaf_line_prefix(&tmp_authmsg, port);
	}

	appendStringInfo(&tmp_authmsg, "%s authentication from %s on port %s",
			prefix, port->remote_host, localport);

	if (tmp_authmsg.len > 0)
	{
		/*
		 * Write a message line to syslog or elog depending on the current
		 * log_destination
		 */
		if (log_destination == PGLAF_SYSLOG)
			write_syslog(LOG_ERR, tmp_authmsg.data);
		else
			elog(LOG, "%s", tmp_authmsg.data);
	}

	pfree(tmp_authmsg.data);
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

static void
start_syslog(void)
{
#ifdef HAVE_SYSLOG
	if (!openlog_done)
	{
		openlog(syslog_ident, LOG_PID | LOG_NDELAY | LOG_NOWAIT, syslog_facility);
		openlog_done = true;
	}
#endif
}

static void
stop_syslog(void)
{
#ifdef HAVE_SYSLOG
	if (openlog_done)
	{
		closelog();
		openlog_done = false;
	}
#endif
}

static void restart_syslog(void)
{
#ifdef HAVE_SYSLOG
	stop_syslog();
	start_syslog();
#endif
}
