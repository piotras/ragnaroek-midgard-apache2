/* $Id: midgard-apache2.c,v 1.49.2.2 2007/06/01 16:41:21 piotras Exp $
 *
 * mod_midgard.c  Midgard address translation and user authentication module
 *                for Apache 2.0
 *
 * Copyright (C) 1999 Jukka Zitting <jukka.zitting@iki.fi>
 * Copyright (C) 2000 The Midgard Project ry
 * Copyright (C) 2001 Emile Heyns <emile@iris-advies.com>, The Midgard Project ry
 * Copyright (C) 2003 Alexander Bokovoy <a.bokovoy@sam-solutions.net>, The Midgard Project ry
 * Copyright (C) 2003 David Schmitter, Dataflow Solutions GmbH <schmitt@dataflow.ch>
 * Copyright (C) 2003 Daniel S. Reichenbach, best off <dsr@best-off.org>
 * Copyright (C) 2004 Alexey A. Zakhlestine <indy@indeyets.pp.ru>
 * Copyright (C) 2005,2006 Piotr Pokora, <pp@infoglob.pl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "httpd.h"

#include <midgard/midgard_apache.h>
#include <midgard/select_db2.h>

#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"
#include "apr_strings.h"
#include <sys/stat.h>

#ifdef APACHE2
# ifndef WIN32

#  include <unistd.h>

#  if APR_HAVE_CTYPE_H
#   include <ctype.h>
#  endif

#ifdef G_LOG_DOMAIN
#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "midgard-core"
#endif

# endif
#endif

/* This is the module definition part for static Apache modules.
 * It tells the Apache configure script to link to the Midgard library
 * that is required by mod_midgard. If libmidgard is not within a normal
 * library directory (/lib, /usr/lib, /usr/local/lib) then you might want
 * to add -L/path/to/lib to the LDFLAGS variable below.
 *
MODULE-DEFINITION-START
Name: midgard
ConfigStart
  LDFLAGS="$LDFLAGS"
  LIBS=`midgard-config --libs`
  CFLAGS=`midgard-config --cppflags`
ConfigEnd
MODULE-DEFINITION-END
 */

#ifdef HAVE_MANDRAKE
# define LIBEXEC_DIR "modules"
#else
# define LIBEXEC_DIR "libexec"
#endif

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Data declarations.                                                       */
/*                                                                          */
/* Here are the static cells and structure declarations private to our      */
/* module.                                                                  */
/*                                                                          */
/*--------------------------------------------------------------------------*/
static int midgard_authenticate (request_rec * r,
				 midgard_server_config * scfg,
				 midgard_request_config * rcfg);
int mgd_get_basic_auth_pw (request_rec * r, const char **usr,
			   const char **pw);

void mgd_note_basic_auth_failure (request_rec * r, midgard * mgd,
				  midgard_server_config * scfg);

void mgd_set_apache_auth_env (request_rec * r, const char *user);

static GSList *database_connection = NULL;
static GSList *database_handle = NULL;

static char *default_rootfile = NULL;
static char *default_parser = "utf-8";
static char *default_extension = ".php";

static int persistent_connect = TRUE;
static int ignore_touched = FALSE;
static int favor_files = TRUE;
static guint logspec = 0;
static char *logfile = NULL;
static MidgardTypeHolder *typeholder = NULL;

/*
 * Declare ourselves so the configuration routines can find and know us.
 * We'll fill it in at the end of the module.
 */
module AP_MODULE_DECLARE_DATA midgard_module;

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* These routines are strictly internal to this module, and support its     */
/* operation.  They are not referenced by any external portion of the       */
/* server.                                                                  */
/*                                                                          */
/*--------------------------------------------------------------------------*/
static const char *
verify_user (midgard_request_config * rcfg)
{
  const char *username;
  const char *password;
  const char *cookie;
  const char *p;
  int reason = 0;

  /* Basic auth */
  if (mgd_get_basic_auth_pw (rcfg->req, &username, &password) == OK
      && ((reason = mgd_auth (rcfg->mgd, username, password, 0)) > 0))
    {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0,
		     rcfg->req, "Midgard: user %s (%d) authorized",
		     username, mgd_user (rcfg->mgd));
      return username;
    }

  if (reason < 0)
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0,
		   rcfg->req, "Midgard: basic auth failed (%s, %d)",
		   VALID_MGD_AUTH_CODE (reason)
		   ? mgd_authfailure_msg[reason]
		   : "Warning: unexpected failure reason", reason);
  else
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0,
		   rcfg->req,
		   "Midgard: no basic auth found, trying cookie auth");

  /* cookie auth */
  request_rec *req = (request_rec *) rcfg->req;
  if ((cookie = apr_table_get(req->headers_in, "Cookie")) == NULL)
    return NULL;

  if ((cookie = strstr(cookie, "MidgardLogin=")) == NULL)
    return NULL;

  cookie += 13;			/* skip MidgardLogin= */

  if ((p = strchr(cookie, ';')) == NULL)
    return NULL;

    cookie = apr_pstrndup(req->pool, cookie, p - cookie);
  cookie = ap_pbase64decode(rcfg->pool, cookie);
  if ((p = strchr(cookie, ':')) == NULL)
    return NULL;

  username = apr_pstrndup(rcfg->pool, cookie, p - cookie);
  password = apr_pstrcat(rcfg->pool, p + 1, NULL);
  if (mgd_auth (rcfg->mgd, username, password, 0) > 0)
    {
      rcfg->auth.cookie = 1;
      return username;
    }

  return NULL;
}

#if HAVE_MIDGARD_MULTILANG
static int
midgard_lang (midgard_request_config * rcfg)
{
  const char *cookie, *p;
  int lang = 0;
  request_rec *req = (request_rec *) rcfg->req;
  if ((cookie = apr_table_get(req->headers_in, "Cookie")) != NULL
      || (cookie =
	  apr_table_get(req->headers_in, "MidgardLang")) != NULL)
    {
      if ((cookie = strstr(cookie, "MidgardLang=")) != NULL)
	{
	  cookie += 12;
	  p = strchr(cookie, ';');
	  if (p)
	    {
	      cookie = apr_pstrndup(req->pool, cookie, p - cookie);
	    }
	  else
	    {
	      cookie = apr_pstrcat(req->pool, cookie, NULL);
	    }
	  lang = atol (cookie);
	}
    }
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, rcfg->req,
		 "Midgard: lang set to %d", lang);
  return lang;
}
#endif /* HAVE_MIDGARD_MULTILANG */

static int
midgard_disconnect_all (server_rec * s)
{
  GSList *list;
  midgard_database_handle *dbh;

  int connections = 0;

  if (database_handle)
    {
      for (list = g_slist_last (database_handle); list != NULL;
	   list = g_slist_next (list))
	{
	  dbh = list->data;
	  if (!dbh)
	    continue;

	  if (dbh->mgd != NULL)
	    {
	      mgd_close (dbh->mgd);
	      dbh->mgd = NULL;
	    }

	  connections++;
	}
    }

  ap_log_error(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, s,
		"Midgard: closing %d database connections", connections);

  return connections;
}

static void
midgard_disconnect_all_and_cleanup (server_rec * s)
{
	GSList *list = NULL;
	midgard_database_handle *dbh;
	midgard_database_connection *dbc;
	
	midgard_disconnect_all (s);
	
	if (database_handle){
		
		for ( ; database_handle; database_handle = database_handle->next){
			
			dbh = database_handle->data;
			if (!dbh)
				continue;
			
			if (dbh->username)
				free (dbh->username);
			if (dbh->password)
				free (dbh->password);
			free (dbh);
		}		
		g_slist_free (database_handle);
		database_handle = NULL;
	}
	
	if (database_connection) {
	
		for (list = g_slist_last (database_connection); list != NULL;
				list = g_slist_next (list)){
			
			dbc = list->data;
			if (!dbc)
				continue;
			
			if (dbc->name)
				free (dbc->name);
			free (dbc);
		}
		g_slist_free (database_connection);
		database_connection = NULL;
	}
	mgd_done ();
}

/* String pointers are equal if both NULL or the strings are equal */
#define SAFECMP(a,b) ((!(a) && !(b)) || ((a) && (b) && !strcmp((a),(b))))

static midgard_database_connection *
midgard_get_database_connection(apr_pool_t * p,
				 const char *database,
				 const char *username, const char *password)
{
  midgard_database_connection *dbc;
  midgard_database_handle *dbh;
  GSList *list;

  const char *hostname = NULL;
  char *delim = NULL;

  if ((delim = strchr(database, ':')) != NULL)
    {
      *delim = '\0';
      hostname = database;
      database = delim + 1;
    }

  dbh = NULL;

  for (list = g_slist_last (database_connection); list != NULL;
       list = g_slist_next (list))
    {

      dbc = list->data;
      if (!dbc || !dbc->handle)
	{
	  fprintf (stderr, "Midgard: error in connection array\n");
	  continue;
	}

      if (!SAFECMP (username, dbc->handle->username)
	  || !SAFECMP (password, dbc->handle->password)
	  || !SAFECMP (hostname, dbc->handle->hostname))
	{
	  continue;
	}

      if (SAFECMP (database, dbc->name))
	{
	  return dbc;
	}

      dbh = dbc->handle;
      break;
    }

  if (dbh == NULL)
    {
      dbh = malloc (sizeof (midgard_database_handle));
      dbh->username = strdup (username);
      dbh->password = strdup (password);
      if (hostname == NULL)
	{
	  dbh->hostname = NULL;
	}
      else
	{
	  dbh->hostname = strdup (hostname);
	}

      dbh->mgd = NULL;
      dbh->current = NULL;
      
      /* FIXME LEAK? */
      database_handle = g_slist_append(database_handle, dbh);

    }

  dbc = malloc (sizeof (midgard_database_connection));
  dbc->name = strdup (database);
  dbc->handle = dbh;

  if (database_connection == NULL)
    {
      database_connection = g_slist_alloc ();
      database_connection->data = dbc;
    }
  else
    {
      database_connection = g_slist_append (database_connection, dbc);
    }

  return dbc;
}

int
mgd_get_basic_auth_pw (request_rec * r, const char **usr, const char **pw)
{
  const char *auth_line = apr_table_get(r->headers_in,
					 (r->proxyreq == PROXYREQ_PROXY)
					 ? "Proxy-Authorization"
					 : "Authorization");

  const char *t;

  if (!auth_line)
    {
      return HTTP_UNAUTHORIZED;
    }

  if (strcasecmp (ap_getword (r->pool, &auth_line, ' '), "Basic"))
    {

      /* Client tried to authenticate using wrong auth scheme */
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r,
		     "client used wrong authentication scheme: %s", r->uri);

      return HTTP_UNAUTHORIZED;
    }

  /* CHARSET_EBCDIC Issue's here ?!? Compare with 32/9 instead
   * as we are operating on an octed stream ?
   */
  while (*auth_line == ' ' || *auth_line == '\t')
    auth_line++;

  t = ap_pbase64decode(r->pool, auth_line);

  /* Note that this allocation has to be made from r->connection->pool
   * because it has the lifetime of the connection.  The other allocations
   * are temporary and can be tossed away any time.
   */
  *usr = ap_getword_nulls (r->connection->pool, &t, ':');
  *pw = t;

  return OK;
}

void
mgd_set_apache_auth_env (request_rec * r, const char *user)
{
  r->user = (char *) user;
  r->ap_auth_type = "Basic";
}

void
mgd_note_basic_auth_failure (request_rec * r, midgard * mgd,
			     midgard_server_config * scfg)
{
	char *realm = "Basic realm=\"Midgard\"";

	midgard_res *res;
	int sitegroup = mgd_sitegroup (mgd);

	if (sitegroup == 0) {
		realm = apr_pstrcat(r->pool, "Basic realm=\"",
				    scfg->default_realm, " (SG0)\"", NULL);
	} else {
		res = mgd_ungrouped_select(mgd, "name,realm", "sitegroup",
					   "id=$d", NULL, sitegroup);

		if (!res || !mgd_fetch (res)) {
			if (res) {
				mgd_release (res);
			}
			realm = apr_pstrcat(r->pool, "Basic realm=\"",
					    scfg->default_realm, "\"", NULL);
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO | APLOG_WARNING,
				      0, r,
				      "Midgard: failed to fetch sitegroup name and realm for "
				      "sitegroup %d", sitegroup);
		} else {
			realm = apr_pstrcat(r->pool, "Basic realm=\"",
			 		    mgd_colvalue (res, 1), " (",
					    mgd_colvalue (res, 0), ")\"", NULL);
		}
	}

  /* Note usage of apr_table_setn() here, we definitely want to provide
     several authentication methods for a client */
	apr_table_setn(r->err_headers_out,
		       r->proxyreq == PROXYREQ_PROXY ? "Proxy-Authenticate" : "WWW-Authenticate",
		       realm);
}

static void *
midgard_create_request_config (request_rec * r)
{
  midgard_request_config *rcfg = (midgard_request_config *)
    apr_pcalloc(r->pool, sizeof (midgard_request_config));

  rcfg->req = (request_rec*)r;
  rcfg->pool = r->pool;
  rcfg->mgd = NULL;

  rcfg->host = 0;
  rcfg->style = 0;
  rcfg->auth.required = 0;
  rcfg->auth.passed = 0;
  rcfg->auth.cookie = 0;
  rcfg->author = 0;

  rcfg->prelen = 0;
  rcfg->self_len = 0;

  rcfg->resource.content_type = NULL;

  rcfg->argv = (apr_array_header_t*)apr_array_make(r->pool, 8, sizeof (const char *));
  
  rcfg->elements = NULL;

  rcfg->database.current = NULL; 
  rcfg->database.main = NULL;

  return (void *) rcfg;
}

static int
midgard_authenticate (request_rec * r, midgard_server_config * scfg,
		      midgard_request_config * rcfg)
{
	const char *username = NULL;
  	/* 
  	const char *password = NULL;
  	const char *auth_resp;
  	*/

	if (scfg->authtrusted || !rcfg->auth.required)
    		return OK;

	if (rcfg->auth.passed)
		return OK;
    	
	if (scfg->database.auth != NULL) {
      		if (!mgd_select_database (rcfg->req, scfg->database.auth, rcfg, TRUE))
	  			return HTTP_UNAUTHORIZED;
     	} else {
      		if (!mgd_select_database (rcfg->req, scfg->database.main, rcfg, FALSE))
		      return HTTP_UNAUTHORIZED;	
	}

	if ((username = verify_user (rcfg)) == NULL) {
		mgd_note_basic_auth_failure (rcfg->req, rcfg->mgd, scfg);
		return HTTP_UNAUTHORIZED;
	}
	
	if (!rcfg->auth.cookie) { 
		mgd_set_apache_auth_env (rcfg->req, username);
     	}
	
	rcfg->auth.passed = 1;
       	if (rcfg->scfg->forcedroot.set && rcfg->scfg->forcedroot.on) {
	  	mgd_force_root (rcfg->mgd);
      	}
       
	return OK;
}

int
setup_pagecache (midgard * mgd,
		 request_rec * r, midgard_request_config * rcfg,
		 midgard_server_config * scfg,
		 midgard_directory_config * dcfg, long sitegroup,
		 GArray * path, mgd_page_t * page)
{
  char *target;
  char *tmp;
  char pageid[40];
  FILE *f;
  int regenerate = FALSE;
  /*
   * struct stat _stat;
   */ 
  mgd_parser_itf_t itf;
  /*
   * time_t cachemark;
   */ 
  FILE *root;
  char *reason = "";
  const char *extension;
  struct stat statbuf;

  sprintf (pageid, "%d-%ld-%ld-%d", rcfg->host, page->page, page->style, mgd_lang (mgd));
  extension = dcfg->extension ? dcfg->extension : default_extension;

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
		 "Midgard: extension = %s, default: %s, parser = %s",
		 extension, default_extension, dcfg->parser);
  target =
    apr_pstrcat(rcfg->pool, scfg->pagecache, "/", pageid, extension, NULL);
  tmp = apr_pstrcat(rcfg->pool, scfg->pagecache, "/", pageid, ".tmp", NULL);

  if (!regenerate && (f = fopen (target, "r")) == NULL)
    {
      regenerate = TRUE;
      reason = "cannot open, assuming non-existant";
      /* FIXME , fixme when module and cache is rewritten.
       * This is acceptable double log message */
      ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, r,
		      "Midgard: regenerating %s: %s", target, reason);
    }
  if (f != NULL) {
	  if((stat(target, &statbuf) == 0)) {
		  /* I think it's safe to make assumption, cache file with less than 10 characters is corrupted or ivalid */
		if (statbuf.st_size < 10) {
			regenerate = TRUE;
			reason = "invalid or corrupted cache";
			ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, r,
					"Midgard: regenerating %s: %s", target, reason);
		}
	  }

      	  fclose (f);
  }

  if (!regenerate && !ignore_touched
      && !mgd_cache_is_current (mgd, rcfg->host, page->page, rcfg->style))
    {
      regenerate = TRUE;
      reason = "no cache entries";
    }

  mgd_load_styles (mgd, path, rcfg->host, page->style, midgard_pc_set_element, rcfg->elements,
		   (regenerate ? 0 : page->page));

  if (regenerate)
    {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
		     "Midgard: regenerating %s: %s", target, reason);

      root = fopen (dcfg->rootfile, "r");
      if (!root){
	      ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0, r,
			      "Can not open MidgardRootFile '%s'", dcfg->rootfile);
	      return FALSE;
      }

      itf.output.func = midgard_pc_output;
      itf.output.userdata = fopen (tmp, "w");

      if (!itf.output.userdata)
	{
	  fclose (root);
	  return FALSE;
	}

/* [eeh] I used to do this as a PHP comment because it doesn't
// output to the browser. Don't replace this by HTML comments
// since it'll break all redirects and cookie stuff
//
//    fprintf(itf.output.userdata, "<?php // SELF");
//    if (page->active) { fprintf(itf.output.userdata, "/active"); }
//    fprintf(itf.output.userdata, "<");
//    fwrite(r->uri, sizeof(char), rcfg->self_len, itf.output.userdata);
//    fprintf(itf.output.userdata, "><%s> // ?>", target);
*/

      itf.get_element.func = midgard_pc_get_element;
      itf.get_element.userdata = rcfg->elements;

      mgd_preparse_file (root, &itf);

      fwrite ("\n", sizeof (char), 1, itf.output.userdata);
      fclose (itf.output.userdata);
      fclose (root);

      rename (tmp, target);
    }

  r->filename = apr_pstrdup (r->pool, target);
  return TRUE;
}

void
setup_root (midgard * mgd, request_rec * r, midgard_request_config * rcfg,
	    midgard_directory_config * dcfg, GArray * path, mgd_page_t * page)
{
  mgd_load_styles (mgd, path, rcfg->host, page->style, midgard_pc_set_element, rcfg->elements,
		   mgd_cache_is_current (mgd, page->page, rcfg->host, 
					 rcfg->style) ? page->page : 0);
  r->filename = dcfg->rootfile ? dcfg->rootfile : default_rootfile;
}

int
blob_request (request_rec * r,
	      midgard_request_config * rcfg, midgard_directory_config * dcfg,
	      mgd_page_t * page)
{
  midgard_res *res;
  const char *location;
  const char *content_type;

  if (dcfg == NULL || dcfg->blobdir == NULL)
    {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0,
		     rcfg->req,
		     "Midgard: No BLOBDIR set, skipping blob search");
      return FALSE;
    }

  res = mgd_ungrouped_select(rcfg->mgd, "location,mimetype",
			      "blobs", "id=$d", NULL, page->blob);

  if (!res || !mgd_fetch (res))
    {
      if (res)
	mgd_release (res);
      return FALSE;
    }

  location = mgd_colvalue (res, 0);
  content_type = mgd_colvalue (res, 1);

  if (!location || location[0] == '\0')
    {
      ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_NOERRNO, 0,
		     rcfg->req,
		     "Midgard: blob %d (on page %ld) has empty location",
		     page->blob, page->page);

      mgd_release (res);
      return FALSE;
    }

  /* BlobDir must start with a '/' and if location looks like a
     relative path we will not serve it.
   */
  if (*(dcfg->blobdir) != '/' || strstr(location, ".."))
    {
      ap_log_rerror(APLOG_MARK, APLOG_CRIT | APLOG_NOERRNO, 0,
		     rcfg->req,
		     "Midgard: BlobDir must start with '/' [%s]",
		     dcfg->blobdir ? dcfg->blobdir : "<NULL blobdir>");
      mgd_release (res);
      return FALSE;
    }

  if (!content_type || content_type[0] == '\0')
    content_type = "application/binary";

  r->filename = apr_pstrcat(rcfg->pool, dcfg->blobdir, "/", location, NULL);
  rcfg->resource.content_type = apr_pstrdup (rcfg->pool, content_type);

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0,
		 rcfg->req,
		 "Midgard: serving blob %s, mimetype=%s",
		 r->filename, content_type);

  mgd_release (res);
  return TRUE;
}

void
store_args (const char *value, void *userdata)
{
  char **arg;
  midgard_request_config *rcfg = (midgard_request_config *) userdata;

  arg = (char **) apr_array_push (rcfg->argv);
  *arg = apr_pstrdup (rcfg->pool, value);
}

/*--------------------------------------------------------------------------*/
/* We prototyped the various syntax for command handlers (routines that     */
/* are called when the configuration parser detects a directive declared    */
/* by our module) earlier.  Now we actually declare a "real" routine that   */
/* will be invoked by the parser when our "real" directive is               */
/* encountered.                                                             */
/*                                                                          */
/* If a command handler encounters a problem processing the directive, it   */
/* signals this fact by returning a non-NULL pointer to a string            */
/* describing the problem.                                                  */
/*                                                                          */
/* The magic return value DECLINE_CMD is used to deal with directives       */
/* that might be declared by multiple modules.  If the command handler      */
/* returns NULL, the directive was processed; if it returns DECLINE_CMD,    */
/* the next module (if any) that declares the directive is given a chance   */
/* at it.  If it returns any other value, it's treated as the text of an    */
/* error message.                                                           */
/*--------------------------------------------------------------------------*/

static const char *MidgardDatabase(
                cmd_parms * cmd, void *dummy,
                const char *database, const char *username, const char *password) {
        midgard_server_config *scfg = (midgard_server_config *)
                ap_get_module_config(cmd->server->module_config, &midgard_module);
        scfg->database.main = midgard_get_database_connection(
                cmd->pool, database, username, password);
        return NULL;
}

static const char *MidgardAuthDatabase(
                cmd_parms * cmd, void *dummy,
                const char *database, const char *username, const char *password) {
        midgard_server_config *scfg = (midgard_server_config *)
                ap_get_module_config(cmd->server->module_config, &midgard_module);
        scfg->database.auth = midgard_get_database_connection(
                cmd->pool, database, username, password);
        scfg->forcedroot.set = 1;
        scfg->forcedroot.on = 1;
        return NULL;
}

static const char *MidgardEngine(cmd_parms *cmd, void *cfg, int flag) {
        midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
        dcfg->engine.on = flag;
        dcfg->engine.set = 1;
        return NULL;
}

static const char *MidgardFavorFiles(cmd_parms *cmd, void *cfg, int flag) {
        favor_files = flag;
        return NULL;
}

static const char *MidgardPersistentConnect(cmd_parms *cmd, void *cfg, int flag) {
        persistent_connect = flag;
        return NULL;
}

static const char *MidgardRootfile(cmd_parms *cmd, void *cfg, const char *rootfile) {
        midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
        dcfg->rootfile = ap_server_root_relative(cmd->pool, rootfile);
        return NULL;
}

static const char *MidgardParser(cmd_parms *cmd, void *cfg, const char *parser) {
        return NULL;
}

static const char *MidgardBlobDir(cmd_parms *cmd, void *cfg, const char *blobdir) {
        midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
        dcfg->blobdir = ap_server_root_relative(cmd->pool, blobdir);
        return NULL;
}

static const char *MidgardDefaultRealm(cmd_parms *cmd, void *cfg, const char *realm) {
        midgard_server_config *scfg = (midgard_server_config *)
                ap_get_module_config(cmd->server->module_config, &midgard_module);
        scfg->default_realm = apr_pstrcat(cmd->pool, realm, NULL);
        return NULL;
}

static const char *MidgardAuth(cmd_parms *cmd, void *cfg, int flag) {
        midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
        dcfg->extauth.on = flag;
        dcfg->extauth.set = 1;
        return NULL;
}

static const char *MidgardTemplate(cmd_parms *cmd, void *cfg, const char *template) {
        midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
        dcfg->templatefile = apr_pstrcat(cmd->pool, template, NULL);
        return NULL;
}

static const char *MidgardPageCacheDir(cmd_parms *cmd, void *cfg, const char *pagecache) {
        midgard_server_config *scfg = (midgard_server_config *)
                ap_get_module_config(cmd->server->module_config, &midgard_module);
        if (pagecache) {
                scfg->pagecache = ap_server_root_relative(cmd->pool, pagecache);
        } else {
                scfg->pagecache = NULL;
        }
        return NULL;
}

static const char *MidgardCacheIgnoreTouched(cmd_parms *cmd, void *cfg, int flag) {
        ignore_touched = flag;
        return NULL;
}

static const char *MidgardLog(cmd_parms *cmd, void *cfg, const char *new_logspec, const char *new_logfile) {
        midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
	logspec = mgd_parse_log_levels(new_logspec);
	dcfg->loglevel = logspec;
	if (new_logfile == NULL) {
		dcfg->logfile = NULL;
        } else {
                dcfg->logfile = apr_pstrcat(cmd->pool, new_logfile, NULL);
        }
        return NULL;
}

static const char *MidgardCacheExtension(cmd_parms *cmd, void *cfg, const char *ext) {
        midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
        dcfg->extension = apr_pstrcat(cmd->pool, ext, NULL);
        return NULL;
}

static const char *MidgardCVSScript(cmd_parms *cmd, void *cfg, const char *ext) {
        midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
        dcfg->cvs_script = apr_pstrcat(cmd->pool, ext, NULL);
        return NULL;
}

static const char *MidgardCheckQuota(cmd_parms *cmd, void *cfg, int flag) {
        midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
        dcfg->quota.on = flag;
        dcfg->quota.set = 1;
        return NULL;
}

static const char *MidgardAttachmentHosts(cmd_parms *cmd, void *cfg, int flag) {
        midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
        dcfg->attachmenthost.on = flag;
        dcfg->attachmenthost.set = 1;
        return NULL;
}

static const char *MidgardAttachmentHostPrefix(cmd_parms *cmd, void *cfg, const char *ext) {
        midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
        dcfg->ah_prefix = apr_pstrcat(cmd->pool, ext, NULL);
        return NULL;
}

static const char *MidgardAuthType(cmd_parms *cmd, void *cfg, const char *authtype) {
        midgard_server_config *scfg = (midgard_server_config *)
                ap_get_module_config(cmd->server->module_config, &midgard_module);

        scfg->authtype = MGD_AUTHTYPE_NORMAL;
        scfg->authtrusted = FALSE;
	if (g_str_equal(authtype, "PAM")) {
		scfg->authtype = MGD_AUTHTYPE_PAM;
        } else if (g_str_equal(authtype, "trusted")) {
		scfg->authtrusted = TRUE;
	}		
        return NULL;
}

static const char *MidgardPamFile(cmd_parms *cmd, void *cfg, const char *pamfile) {
	midgard_server_config *scfg = (midgard_server_config *)
		ap_get_module_config(cmd->server->module_config, &midgard_module);
	
	scfg->pamfile = pamfile;
	return NULL;
}

/* DO NOT try to register schema and types at this point.
 * This command is called much much earlier than module_init.
 * Apache modules should be responsible for registering types and schemas. 
 * Or we should provide some 'plug-in' functionality if we want to 
 * share data between different midgard modules for Apache.
 */ 
static const char *MidgardSchemaCmd(cmd_parms *cmd, void *cfg, const char *sch) {
        midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
        dcfg->schemafile = sch;
        return NULL;
}

static const char *MidgardConfigFile(cmd_parms *cmd, void *cfg, const char *filename) {
	
	midgard_directory_config *dcfg = (midgard_directory_config *) cfg;
	midgard_server_config *scfg = (midgard_server_config *)
		ap_get_module_config(cmd->server->module_config, &midgard_module);

	const gchar *dbstring, *host, *database, *username, *password, *blobdir, *new_logfile;
	const gchar *schemafile;

	g_type_init(); 
	
	MidgardConfig *config = g_object_new(MIDGARD_TYPE_CONFIG, NULL);
	/* g_warning("getting config"); */
  /* TODO use <<ap_log_rerror>> to log this warning */
	if(!midgard_config_read_file(config, filename, FALSE)){
		g_error("Midgard configuration file read failed!");
		return NULL;
	}

	g_object_get(G_OBJECT(config),
      			"host", &host, 
			"database", &database,
			"dbuser", &username,
			"dbpass", &password,
			"blobdir", &blobdir,
			"logfilename", &new_logfile,
			"schema", &schemafile,
			NULL);
	
	/* FIXME */
	/* Change this to dcfg->config = config */
	
	/* FIXME , change to midgard_get_database_connection(cmd->pool, config) */
  	dbstring = g_strconcat(host, ":", database, NULL);
	scfg->database.main = midgard_get_database_connection(
			cmd->pool, dbstring, username, password);

	dcfg->blobdir = ap_server_root_relative(cmd->pool, blobdir);

	if (new_logfile == NULL) {
		logfile = NULL;
	} else {
		logfile = apr_pstrcat(cmd->pool, new_logfile, NULL);
	}
	
	dcfg->schemafile = schemafile;
	
	dcfg->engine.on = 1;
	dcfg->engine.set = 1;

#ifdef DEFAULT_EXP_LIBEXECDIR
	dcfg->rootfile = ap_server_root_relative(cmd->pool, 
			g_strconcat(DEFAULT_EXP_LIBEXECDIR, "/midgard-root.php", NULL));
#endif
	return NULL;
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Now let's declare routines for each of the callback phase in order.      */
/* (That's the order in which they're listed in the callback list, *not     */
/* the order in which the server calls them!  See the command_rec           */
/* declaration near the bottom of this file.)  Note that these may be       */
/* called for situations that don't relate primarily to our function - in   */
/* other words, the fixup handler shouldn't assume that the request has     */
/* to do with "example" stuff.                                              */
/*                                                                          */
/* With the exception of the content handler, all of our routines will be   */
/* called for each request, unless an earlier handler from another module   */
/* aborted the sequence.                                                    */
/*                                                                          */
/* Handlers that are declared as "int" can return the following:            */
/*                                                                          */
/*  OK          Handler accepted the request and did its thing with it.     */
/*  DECLINED    Handler took no action.                                     */
/*  HTTP_mumble Handler looked at request and found it wanting.             */
/*                                                                          */
/* What the server does after calling a module handler depends upon the     */
/* handler's return value.  In all cases, if the handler returns            */
/* DECLINED, the server will continue to the next module with an handler    */
/* for the current phase.  However, if the handler return a non-OK,         */
/* non-DECLINED status, the server aborts the request right there.  If      */
/* the handler returns OK, the server's next action is phase-specific;      */
/* see the individual handler comments below for details.                   */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/*
 * This function gets called to create a per-directory configuration
 * record.  This will be called for the "default" server environment, and for
 * each directory for which the parser finds any of our directives applicable.
 * If a directory doesn't have any of our directives involved (i.e., they
 * aren't in the .htaccess file, or a <Location>, <Directory>, or related
 * block), this routine will *not* be called - the configuration for the
 * closest ancestor is used.
 *
 * The return value is a pointer to the created module-specific
 * structure.
 */
static void *
midgard_create_directory_config (apr_pool_t * p, char *dir)
{

  midgard_directory_config *dcfg = (midgard_directory_config *)
    apr_palloc (p, sizeof (midgard_directory_config));

  dcfg->engine.on = 0;
  dcfg->engine.set = 0;

  dcfg->extauth.on = 0;
  dcfg->extauth.set = 0;

  dcfg->rootfile = NULL;
  dcfg->blobdir = NULL;
  dcfg->cvs_script = NULL;
  dcfg->quota.on = 0;
  dcfg->quota.set = 0;
  dcfg->attachmenthost.on = 0;
  dcfg->attachmenthost.set = 0;
  dcfg->ah_prefix = NULL;
  dcfg->parser = default_parser;
  dcfg->extension = default_extension;
  dcfg->schema = NULL;
  dcfg->schemafile = NULL;
  dcfg->logfile = NULL;
  dcfg->loglevel = mgd_parse_log_levels("warn");

  return (void *) dcfg;
}

/*
 * This function gets called to merge two per-directory configuration
 * records.  This is typically done to cope with things like .htaccess files
 * or <Location> directives for directories that are beneath one for which a
 * configuration record was already created.  The routine has the
 * responsibility of creating a new record and merging the contents of the
 * other two into it appropriately.  If the module doesn't declare a merge
 * routine, the record for the closest ancestor location (that has one) is
 * used exclusively.
 *
 * The routine MUST NOT modify any of its arguments!
 *
 * The return value is a pointer to the created module-specific structure
 * containing the merged values.
 */
static void *
midgard_merge_directory_config (apr_pool_t * p, void *base, void *new)
{
  midgard_directory_config *dcfg_base = (midgard_directory_config *) base;
  midgard_directory_config *dcfg_new = (midgard_directory_config *) new;
  midgard_directory_config *dcfg = (midgard_directory_config *)
    apr_palloc (p, sizeof (midgard_directory_config));

  dcfg->engine.on =
    dcfg_new->engine.set ? dcfg_new->engine.on : dcfg_base->engine.on;
  dcfg->engine.set = dcfg_new->engine.set || dcfg_base->engine.set;

  dcfg->extauth.on =
    dcfg_new->extauth.set ? dcfg_new->extauth.on : dcfg_base->extauth.on;
  dcfg->extauth.set = dcfg_new->extauth.set || dcfg_base->extauth.set;

  dcfg->rootfile = apr_pstrcat(p, dcfg_new->rootfile ?
				dcfg_new->rootfile : dcfg_base->rootfile, NULL);

  dcfg->blobdir = apr_pstrcat(p, dcfg_new->blobdir ?
			       dcfg_new->blobdir : dcfg_base->blobdir, NULL);
  dcfg->cvs_script = apr_pstrcat(p, dcfg_new->cvs_script ?
				  dcfg_new->cvs_script : dcfg_base->
				  cvs_script, NULL);
	dcfg->quota.on =
    dcfg_new->quota.set ? dcfg_new->quota.on : dcfg_base->quota.on;
	dcfg->attachmenthost.on =
    dcfg_new->attachmenthost.set ? dcfg_new->attachmenthost.on : dcfg_base->
    attachmenthost.on;
	dcfg->ah_prefix =
    dcfg_new->ah_prefix ? dcfg_new->ah_prefix : dcfg_base->ah_prefix;
  if (!dcfg->ah_prefix)
    {
      dcfg->ah_prefix = "serveattachment";
    }
  dcfg->parser = apr_pstrcat(p, dcfg_new->parser ?
			      dcfg_new->parser : dcfg_base->parser, NULL);
  dcfg->extension = apr_pstrcat(p, dcfg_new->extension ?
				 dcfg_new->extension : dcfg_base->extension, NULL); 
  dcfg->schema = dcfg_new->schema ? dcfg_new->schema : dcfg_base->schema;
  dcfg->schemafile = dcfg_new->schemafile ? dcfg_new->schemafile : dcfg_base->schemafile;
  dcfg->logfile = dcfg_new->logfile ? dcfg_new->logfile : dcfg_base->logfile;
  dcfg->loglevel = dcfg_new->loglevel ? dcfg_new->loglevel : dcfg_base->loglevel;
  return (void *) dcfg;
}

/*
 * This function gets called to create a per-server configuration
 * record.  It will always be called for the "default" server.
 *
 * The return value is a pointer to the created module-specific
 * structure.
 */
static void *
midgard_create_server_config (apr_pool_t * p, server_rec * s)
{
  midgard_server_config *scfg = (midgard_server_config *)
    apr_palloc (p, sizeof (midgard_server_config));

  scfg->default_realm = "Midgard"; 
  scfg->database.auth = NULL;
  scfg->database.main = NULL;
  scfg->forcedroot.set = 0;
  scfg->pagecache = NULL;
  scfg->authtype = MGD_AUTHTYPE_NORMAL;
  scfg->authtrusted = FALSE;
  scfg->pamfile = "midgard";
 
  return (void *) scfg;
}

/*
 * This function gets called to merge two per-server configuration
 * records.  This is typically done to cope with things like virtual hosts and
 * the default server configuration  The routine has the responsibility of
 * creating a new record and merging the contents of the other two into it
 * appropriately.  If the module doesn't declare a merge routine, the more
 * specific existing record is used exclusively.
 *
 * The routine MUST NOT modify any of its arguments!
 *
 * The return value is a pointer to the created module-specific structure
 * containing the merged values.
 */
static void *
midgard_merge_server_config (apr_pool_t * p, void *base, void *new)
{
  midgard_server_config *scfg_base = (midgard_server_config *) base;
  midgard_server_config *scfg_new = (midgard_server_config *) new;
  midgard_server_config *scfg = (midgard_server_config *)
    apr_pcalloc(p, sizeof (midgard_server_config));

  /* Can only be used outside of VirtualHost directives */
  scfg->default_realm = apr_pstrcat(p, scfg_new->default_realm ?
				     scfg_new->default_realm : scfg_base->
				     default_realm, NULL);

  /* Inherit the database to be used */
  scfg->database.auth =
    scfg_new->database.auth
    ? scfg_new->database.auth : scfg_base->database.auth;
  scfg->database.main =
    scfg_new->database.main
    ? scfg_new->database.main : scfg_base->database.main;

  scfg->forcedroot.on =
    scfg_new->forcedroot.set ? scfg_new->forcedroot.on : scfg_base->
    forcedroot.on;
  scfg->forcedroot.set = scfg_new->forcedroot.set
    || scfg_base->forcedroot.set;
  scfg->pagecache =
    apr_pstrcat(p,
		 scfg_new->pagecache ? scfg_new->pagecache : scfg_base->
		 pagecache, NULL);

  if (scfg_new->authtype != scfg->authtype) {
    scfg->authtype = scfg_new->authtype;
  }
  if (scfg_new->authtrusted != scfg->authtrusted) {
    scfg->authtrusted = scfg_new->authtrusted;
  }

  scfg->pamfile = scfg_new->pamfile  ? scfg_new->pamfile : scfg_base->pamfile;
  if(scfg->pamfile == NULL)
	  scfg->pamfile = "midgard";
  return (void *) scfg;
}

/*
 * This routine is called when our process dies.
 */
static apr_status_t
midgard_child_exit (void * s)
{
  midgard_disconnect_all_and_cleanup (s);
  return APR_SUCCESS;
}

/*
 * This is our process initialiser which is called when a child comes to live.
 */
static void
midgard_child_init (apr_pool_t * p, server_rec * s)
{
	/* midgard_server_config *scfg = (midgard_server_config *)  */ 
	/* ap_get_module_config(s->module_config, &midgard_module); */

	/* Initialize the default rootfile setting. */

#ifdef DEFAULT_EXP_LIBEXECDIR
	default_rootfile =
		ap_server_root_relative(p, DEFAULT_EXP_LIBEXECDIR "/midgard-root.php");
#endif
}

/*
 * This routine is called to perform any module-specific fixing of header
 * fields, et cetera.  It is invoked just before any content-handler.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, the
 * server will still call any remaining modules with an handler for this
 * phase.
 */
static int
midgard_module_init (apr_pool_t * p, apr_pool_t * plog,
		     apr_pool_t * ptemp, server_rec * s)
{
	const char *component;
	component = apr_pstrcat(p, "Midgard/", MIDGARD_LIB_VERSION, NULL);
	ap_add_version_component(p, component);

	g_type_init();
	mgd_init_ex(logspec, logfile);
	default_parser = apr_pstrcat(p, "utf-8", NULL);
	apr_pool_cleanup_register(p, s, midgard_child_exit, midgard_child_exit);

	return OK;
}

/*
 * This routine gives our module an opportunity to translate the URI into an
 * actual filename.  If we don't do anything special, the server's default
 * rules (Alias directives and the like) will continue to be followed.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, no
 * further modules are called for this phase.
 */
static int
midgard_translate_handler (request_rec * r)
{
	midgard_server_config *scfg;
	midgard_directory_config *dcfg;
	midgard_request_config *rcfg;
	mgd_host_t host;
	mgd_page_t page;
	const char *parser;
	GArray *path;
	char *uri;
	int urilen, pclen;
	int auth_res, lang;
	request_rec *subreq;

	/* I am blind and looking for best place where GType system can be initialized 
	 * MidgardConnection handler must be initialized even for non midgard requests,
	 * so g_type_init is invoked here. Looks like it is safe to call it with every 
	 * request */ 
	g_type_init();

	/* we don't do subrequests */
	if (r->main != NULL)
		return DECLINED;

#if MIDGARD_PHP_REQUEST_CONFIG_BUG_WORKAROUND
	mgd_php_bug_workaround_set_rcfg_dcfg (NULL, NULL);
#endif
	/* Check whether MidgardEngine is on */
	dcfg = (midgard_directory_config *)
		ap_get_module_config(r->per_dir_config, &midgard_module);
	if (!dcfg || !dcfg->engine.on)
		return DECLINED;

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
			"midgard_translate_handler(%s, http://%s:%d%s)",
			dcfg->parser ? dcfg->parser : default_parser,
			ap_get_server_name (r), ap_get_server_port (r), r->uri);
	/* Check that the Midgard database is available */
	scfg = (midgard_server_config *)
		ap_get_module_config(r->server->module_config, &midgard_module);
	
	if (!scfg || !scfg->database.main){
		ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
				"Midgard: database not defined for %s",
				ap_get_server_name (r));
		return DECLINED;
	}
	
	/* Create the request config record */
	rcfg = (midgard_request_config *) midgard_create_request_config (r);
	rcfg->scfg = scfg;
	
	if (!mgd_select_database (r, scfg->database.main, rcfg, TRUE))
		return HTTP_SERVICE_UNAVAILABLE;
	
	if (scfg->database.main->handle == NULL
			|| scfg->database.main->handle->mgd == NULL) {
		
		ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
				"Midgard: error opening database connection for %s to %s as %s",
				ap_get_server_name (r),
				scfg->database.main->name,
				scfg->database.main->handle->username);

		return HTTP_SERVICE_UNAVAILABLE;
	}
	
	mgd_clear (rcfg->mgd, MGD_CLEAR_ALL);
	parser = dcfg->parser ? dcfg->parser : default_parser;
	mgd_select_parser (rcfg->mgd, parser);
	
	rcfg->database.main = scfg->database.main;
	
	mgd_find_host (rcfg->mgd,
			ap_get_server_name (r), ap_get_server_port (r), r->uri,
			0, &host);
	if (!host.found) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
				"Midgard: host record for %s:%d not found",
				ap_get_server_name (r), ap_get_server_port (r));
		return DECLINED;
	}

  /*[eeh]  determine translated filename + handler by subrequest
   *       _unless_ we're requesting the root page. The root page will
   *       generally resolve to the docroot, and that'll allways
   *       match in favor of the midgard request => root page
   *       unreachable. Another way would be to check for
   *       directories, but given the fact that most people
   *       (including me) like and use directory => index.html
   *       mapping, I'd rather use this hack.
   */
  urilen = strlen (r->uri);
  /* remove trailing '/' since prefixes in the midgard database
   * should not have them
   */
  if (urilen > 0 && r->uri[urilen - 1] == '/') {
    urilen--;
  }
  
  if (favor_files && host.prefix_length != urilen)  {
    
    if ((subreq = ap_sub_req_lookup_uri (r->uri, r, NULL)) != NULL
        && subreq->finfo.filetype != APR_NOFILE) {

      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
          "Midgard: file %s exists [%s], not serving from database",
          subreq->filename, subreq->content_type);
      
      ap_destroy_sub_req (subreq);
      return DECLINED;
    }
    ap_destroy_sub_req (subreq);
  }

  /* copy found values */
  rcfg->host = host.host;
  rcfg->prelen = host.prefix_length;
  mgd_set_sitegroup (rcfg->mgd, host.sitegroup);

  lang = midgard_lang (rcfg);
  if (lang == 0){
    lang = host.lang;
  }
  
  mgd_internal_set_lang (rcfg->mgd, lang);
  mgd_set_default_lang(rcfg->mgd, 0);

  /* find page */
  path = g_array_new (FALSE, FALSE, sizeof (long));
  mgd_parse_uri (rcfg->mgd, &host, r->uri, &page, store_args, path, rcfg);

  rcfg->style = page.style;
  rcfg->resource.id = page.page;
  rcfg->author = page.author;
  rcfg->self_len = page.self_len;
  rcfg->auth.required = page.auth_required;

  mgd_set_authtype(rcfg->mgd, scfg->authtype);
  rcfg->mgd->pamfile = scfg->pamfile;

  switch (page.found) {

    case MGD_FOUND_NONE:
      
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
          "Midgard: no page or blob record for '%s'", r->uri);
      g_array_free (path, TRUE);
      return DECLINED;

    case MGD_FOUND_PAGE:

      if ((auth_res = midgard_authenticate (r, scfg, rcfg)) != OK){
        
        g_array_free (path, TRUE);
        return auth_res;
      }
      break;
      
      /* rest handled below */
      
    case MGD_FOUND_BLOB:

      g_array_free (path, TRUE);
      if ((auth_res = midgard_authenticate (r, scfg, rcfg)) != OK) {
        return auth_res;
      }

      if (blob_request (r, rcfg, dcfg, &page)){
        /* store rcgf so the type_checker can find it later */
        ap_set_module_config (r->request_config, &midgard_module,
            (void *) rcfg);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
            "Midgard: serving blob %s", r->filename);
        
        return OK;
      }

      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
		     "Midgard: Error serving blob %d", page.blob);

      return DECLINED;

    default:
      
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
		     "Midgard: Unexpected uri parse result %d for '%s'",
		     page.found, r->uri);
      g_array_free (path, TRUE);
      return DECLINED;
    }

  /* rcfg->preparser_active = (scfg->pagecache != NULL);
   * PP check if PageCacheDir length is greater then 0
   * for some reason some Apache2 API function returns either /0
   * or "" for this path.
   * */
  
  if (scfg->pagecache == NULL) {
    pclen = 0 ;
  } else {
    pclen = strlen((char*)scfg->pagecache);
  }

  /* Initialize elements for mmp and nommp root files */
  rcfg->elements = midgard_hash_strings_new(); 
       
  if (scfg->pagecache != NULL && pclen > 0) {
    if (!setup_pagecache (rcfg->mgd, r, rcfg, scfg, dcfg, host.sitegroup,
          path, &page))	{
      
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
          "Midgard: Couldn't create cache file");
      g_array_free (path, TRUE);
      
      return DECLINED;
    }
  } else {
    setup_root (rcfg->mgd, r, rcfg, dcfg, path, &page);
  }

  g_array_free (path, TRUE);

  /* Seems like we do not need to select database again. */
  /*
  if (!mgd_select_database (r, scfg->database.main, rcfg, FALSE)) {
    return DECLINED;
  }
  mgd_set_authtype(rcfg->mgd, scfg->authtype);
  */

  if (page.addslash)  {
    uri = r->args
      ? apr_pstrcat(r->pool, ap_escape_uri (r->pool, r->uri), "/",
          "?", r->args, NULL)
	: apr_pstrcat(r->pool, ap_escape_uri (r->pool, r->uri), "/", NULL);

      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
		     "Midgard: redirecting to %s", uri);

      apr_table_set(r->headers_out, "Location",
		    ap_construct_url (r->pool, uri, r));

      return HTTP_MOVED_PERMANENTLY;
    }

  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
		 "Midgard: serving page %s", r->filename);

  /* Store the gathered information for Midgard/PHP */
  ap_set_module_config (r->request_config, &midgard_module, (void *) rcfg);
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
		 "Midgard: setting blobdir %s", dcfg->blobdir);
  mgd_set_blobdir (rcfg->mgd, dcfg->blobdir);
#if HAVE_MIDGARD_VC
  mgd_set_cvs_script (rcfg->mgd, dcfg->cvs_script);
#endif /* HAVE_MIDGARD_VC */

#if HAVE_MIDGARD_QUOTA
  mgd_set_quota (rcfg->mgd, dcfg->quota.on);
#endif /* HAVE_MIDGARD_QUOTA */
  if (dcfg->attachmenthost.on)
    {
      mgd_set_ah_prefix (rcfg->mgd, dcfg->ah_prefix);
    }
#if MIDGARD_PHP_REQUEST_CONFIG_BUG_WORKAROUND
  mgd_php_bug_workaround_set_rcfg_dcfg (rcfg, dcfg);
#endif

  apr_array_header_t *_argv = (apr_array_header_t*) rcfg->argv;
  request_rec *req = (request_rec *) rcfg->req;	
  
  rcfg->uri = req->uri;
  rcfg->nelts = _argv->nelts;
  rcfg->elts = (char**)_argv->elts;

	if(dcfg->loglevel)
		rcfg->mgd->loglevel = dcfg->loglevel;
	else
		rcfg->mgd->loglevel = mgd_parse_log_levels("warn");

	typeholder = g_new(MidgardTypeHolder, 1);
	typeholder->level = rcfg->mgd->loglevel;
	rcfg->mgd->loghandler =
		g_log_set_handler(G_LOG_DOMAIN, G_LOG_LEVEL_MASK,
				mgd_log_debug_default, (gpointer)typeholder);
  
  return OK;
}

/*
 * This routine is called to check the authentication information sent with
 * the request (such as looking up the user in a database and verifying that
 * the [encrypted] password sent matches the one in the database).
 *
 * The return value is OK, DECLINED, or some HTTP_mumble error (typically
 * HTTP_UNAUTHORIZED).  If we return OK, no other modules are given a chance
 * at the request during this phase.
 */
static int
midgard_host_auth (request_rec * r)
{
  midgard_request_config rcfg;
  midgard_server_config *scfg;
  midgard_directory_config *dcfg;
  mgd_host_t host;
  const char *parser;
  int auth_res;
    
  
  /* Check whether MidgardEngine is on */
  dcfg = (midgard_directory_config *)
    ap_get_module_config(r->per_dir_config, &midgard_module);
  if (!dcfg || !dcfg->extauth.on)
    return DECLINED;

  /* Check that the Midgard database is available */
  scfg = (midgard_server_config *)
    ap_get_module_config(r->server->module_config, &midgard_module);

  if (!scfg || (!scfg->database.auth && !scfg->database.main) ||
      (!scfg->database.auth->handle && !scfg->database.main->handle))
    {
      ap_log_rerror(APLOG_MARK, APLOG_ERR | APLOG_NOERRNO, 0, r,
		     "Midgard: (authen) database not defined for %s",
		     ap_get_server_name (r));
      return DECLINED;
    }

  if (scfg->database.auth)
    mgd_select_database (r, scfg->database.auth, &rcfg, TRUE);
  else
    mgd_select_database (r, scfg->database.main, &rcfg, TRUE);

  if (!rcfg.mgd)
    return DECLINED;

  rcfg.scfg = scfg;
  mgd_clear (rcfg.mgd, MGD_CLEAR_ALL);
  parser = dcfg->parser ? dcfg->parser : default_parser;
  mgd_select_parser (rcfg.mgd, parser);

  rcfg.req = r;

  mgd_find_host (rcfg.mgd,
		 ap_get_server_name (r), ap_get_server_port (r), r->uri,
		 0, &host);

  if (!host.found)
    {
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0, r,
		     "Midgard: host record for %s:%d not found",
		     ap_get_server_name (r), ap_get_server_port (r));
      mgd_close (rcfg.mgd);
      return DECLINED;
    }

  rcfg.host = host.host;
  rcfg.style = host.style;
  rcfg.resource.id = host.page;
  rcfg.auth.required = host.auth_required;
  rcfg.auth.passed = 0;
  rcfg.prelen = host.prefix_length;
  mgd_set_sitegroup (rcfg.mgd, host.sitegroup);

  mgd_select_database (r, scfg->database.main, &rcfg, FALSE);
  if ((auth_res = midgard_authenticate (r, scfg, &rcfg)) != OK)
    {
      mgd_close (rcfg.mgd);
      return auth_res;
    }

  if (rcfg.auth.cookie)
    {
      return DECLINED;
    }

  mgd_close (rcfg.mgd);
  return OK;
}

static int midgard_fixup(request_rec *r) {
        midgard_request_config *rcfg = (midgard_request_config *)
                ap_get_module_config(r->request_config, &midgard_module);
        midgard_server_config *scfg = (midgard_server_config *)
                ap_get_module_config(r->server->module_config, &midgard_module);

        if (!rcfg || !scfg || !scfg->authtrusted) {
                return DECLINED;
        }
        if (r->user && mgd_auth_trusted(rcfg->mgd, r->user) >= 0) {
                return OK;
        } else if (rcfg->auth.required) {
                return HTTP_UNAUTHORIZED;
        } else {
                return DECLINED;
        }
}

/*
 * This routine is called to determine and/or set the various document type
 * information bits, like Content-type (via r->content_type), language, et
 * cetera.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, no
 * further modules are given a chance at the request for this phase.
 */
static int
midgard_type_checker (request_rec * r)
{
  midgard_request_config *rcfg = (midgard_request_config *)
    ap_get_module_config(r->request_config, &midgard_module);

  if (!rcfg)
    return DECLINED;

  if (rcfg->resource.content_type != NULL)
    {
      r->content_type = rcfg->resource.content_type;

      ap_log_rerror(APLOG_MARK, APLOG_DEBUG | APLOG_NOERRNO, 0,
		     rcfg->req,
		     "Midgard: smurfing type to %s", r->content_type);
      return OK;
    }

  return DECLINED;
}

/*
 * This routine is called to perform any module-specific logging activities
 * over and above the normal server things.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, any
 * remaining modules with an handler for this phase will still be called.
 */
static int
midgard_request_end (request_rec * r)
{
  if (!persistent_connect)
    midgard_disconnect_all (r->server);

  return DECLINED;
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Which functions are responsible for which hooks in the server.           */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/* 
 * Each function our module provides to handle a particular hook is
 * specified here.  The functions are registered using 
 * ap_hook_foo(name, predecessors, successors, position)
 * where foo is the name of the hook.
 *
 * The args are as follows:
 * name         -> the name of the function to call.
 * predecessors -> a list of modules whose calls to this hook must be
 *                 invoked before this module.
 * successors   -> a list of modules whose calls to this hook must be
 *                 invoked after this module.
 * position     -> The relative position of this module.  One of
 *                 APR_HOOK_FIRST, APR_HOOK_MIDDLE, or APR_HOOK_LAST.
 *                 Most modules will use APR_HOOK_MIDDLE.  If multiple
 *                 modules use the same relative position, Apache will
 *                 determine which to call first.
 *                 If your module relies on another module to run first,
 *                 or another module running after yours, use the 
 *                 predecessors and/or successors.
 *
 * The number in brackets indicates the order in which the routine is called
 * during request processing.  Note that not all routines are necessarily
 * called (such as if a resource doesn't have access restrictions).
 * The actual delivery of content to the browser [9] is not handled by
 * a hook; see the handler declarations below.
 */
static void
midgard_register_hooks (apr_pool_t * p)
{
  ap_hook_check_user_id (midgard_host_auth, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_fixups (midgard_fixup, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_child_init (midgard_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_log_transaction (midgard_request_end, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_config (midgard_module_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_translate_name (midgard_translate_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_type_checker (midgard_type_checker, NULL, NULL, APR_HOOK_MIDDLE);
}

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* All of the routines have been declared now.  Here's the list of          */
/* directives specific to our module, and information about where they      */
/* may appear and how the command parser should pass them to us for         */
/* processing.  Note that care must be taken to ensure that there are NO    */
/* collisions of directive names between modules.                           */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/* 
 * List of directives specific to our module.
 */

#define COMMAND(type, directive, doc) \
        AP_INIT_ ## type(#directive, directive, NULL, RSRC_CONF|ACCESS_CONF, doc)

static const command_rec midgard_cmds[] = {
        COMMAND(FLAG,   MidgardEngine,               "On or Off to enable or disable (default) the Midgard engine"),
        COMMAND(TAKE3,  MidgardDatabase,             "Name of the Midgard database, username and password from which to fetch content"), 
        COMMAND(TAKE3,  MidgardAuthDatabase,         "Name of the Midgard database, username and password from which to authenticate"),
        COMMAND(FLAG,   MidgardFavorFiles,           "On or Off to favor files or midgard urls when both match"),
        COMMAND(FLAG,   MidgardPersistentConnect,    "On or Off to enable (default) or disable persistent database connections"),
        COMMAND(TAKE1,  MidgardRootfile,             "Location of the Midgard root file"),
        COMMAND(TAKE1,  MidgardParser,               "Obsolete"),
        COMMAND(TAKE1,  MidgardBlobDir,              "Location of the Midgard BLOBs"),
        COMMAND(TAKE1,  MidgardDefaultRealm,         "Default Midgard Basic Auth Realm"),
        COMMAND(FLAG,   MidgardAuth,                 "On or Off to enable or disable (default) Midgard Auth for non-midgard requests"),
        COMMAND(TAKE1,  MidgardTemplate,             "Name of the Midgard filetemplate style element files"),
        COMMAND(TAKE1,  MidgardPageCacheDir,         "Location of the Midgard page cache"),
        COMMAND(FLAG,   MidgardCacheIgnoreTouched,   "Ignore the fact that objects are touched and only regenerate when the cache file is missing"),
        COMMAND(TAKE12, MidgardLog,                  "LogLevel mask and optional logfile (default is to log to the apache error log"),
        COMMAND(TAKE1,  MidgardCacheExtension,       "Exptension for cached PHP script"),
        COMMAND(TAKE1,  MidgardCVSScript,            "Location of the CVS and replication script, config parameter"),
        COMMAND(FLAG,   MidgardCheckQuota,           "If quota limits should be checked on create / update"),
        COMMAND(FLAG,   MidgardAttachmentHosts,      "If attachment hosts should be emulated"),
        COMMAND(TAKE1,  MidgardAttachmentHostPrefix, "Location of the CVS and replication script, config parameter"),
        COMMAND(TAKE1,  MidgardAuthType,             "Name of the Midgard authentication type (use AM for enforcing PAM authentication)"),
        COMMAND(TAKE1,  MidgardSchemaCmd,               "Location of the Midgard xml schema"),
	COMMAND(TAKE1,  MidgardConfigFile,              "Name of the Midgard configuration file"),
	COMMAND(TAKE1,  MidgardPamFile,			"Name of the file used with PAM authentication type"),
	{ NULL }
};

/*--------------------------------------------------------------------------*/
/*                                                                          */
/* Finally, the list of callback routines and data structures that provide  */
/* the static hooks into our module from the other parts of the server.     */
/*                                                                          */
/*--------------------------------------------------------------------------*/
/* 
 * Module definition for configuration.  If a particular callback is not
 * needed, replace its routine name below with the word NULL.
 */
module AP_MODULE_DECLARE_DATA midgard_module = {
  STANDARD20_MODULE_STUFF,
  midgard_create_directory_config,	/* per-directory config creator */
  midgard_merge_directory_config,	/* dir config merger */
  midgard_create_server_config,	/* server config creator */
  midgard_merge_server_config,	/* server config merger */
  midgard_cmds,			/* command table */
  midgard_register_hooks,	/* set up other request processing hooks */
};
