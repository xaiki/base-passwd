/* update-passwd - Safely update /etc/passwd, /etc/shadow and /etc/group
 * Copyright (C) 1999 Software in the Public Interest.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 
 *
 * Written by Wichert Akkerman <wakkerma@debian.org>, based on an earlier
 * attempt from Galen Hazelwood <galenh@micron.net>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>
#include <paths.h>
#include <pwd.h>
#include <shadow.h>
#include <grp.h>

#define VERSION			"3.1.1"

#define DEFAULT_PASSWD_MASTER	"/usr/share/base-passwd/passwd.master"
#define DEFAULT_GROUP_MASTER	"/usr/share/base-passwd/group.master"

#define	WRITE_EXTENSION		".upwd-write"
#define	UNLINK_EXTENSION	".upwd-unlink"

#define LINESIZE		1024


#define FL_KEEPHOME	0x0001
#define FL_KEEPSHELL	0x0002
#define FL_KEEPGECOS	0x0004
#define FL_KEEPALL	0x000f

#define FL_NOAUTOREMOVE	0x0010
#define FL_NOAUTOADD	0x0020

/* This structure is actually used for both users and groups
 * we probably should split that sometime.
 */
const struct _userinfo {
    unsigned	id;
    unsigned	flags;
} specialusers[] = {
    { /* root */     0,	(FL_KEEPALL|FL_NOAUTOREMOVE)				},
    { /* ftp  */    11,	(FL_KEEPHOME|FL_NOAUTOADD|FL_NOAUTOREMOVE)		},
    { /* www-data*/ 33,	(FL_KEEPHOME)						},
    { /* alias:qmail */   70, (FL_NOAUTOREMOVE)					},
    { /* qmaild*/   71, (FL_KEEPALL|FL_KEEPHOME|FL_NOAUTOADD|FL_NOAUTOREMOVE)	}, /* actually only a user */
    { /* qmails*/   72, (FL_KEEPALL|FL_KEEPHOME|FL_NOAUTOADD|FL_NOAUTOREMOVE)	}, /* actually only a user */
    { /* qmailr*/   73, (FL_KEEPALL|FL_KEEPHOME|FL_NOAUTOADD|FL_NOAUTOREMOVE)	}, /* actually only a user */
    { /* qmailq*/   74, (FL_KEEPALL|FL_KEEPHOME|FL_NOAUTOADD|FL_NOAUTOREMOVE)	}, /* actually only a user */
    { /* qmaill*/   75, (FL_KEEPALL|FL_KEEPHOME|FL_NOAUTOADD|FL_NOAUTOREMOVE) 	}, /* actually only a user */
    { /* qmailp*/   76, (FL_KEEPALL|FL_KEEPHOME|FL_NOAUTOADD|FL_NOAUTOREMOVE)	}, /* actually only a user */
    { 0, 0}
};


struct _node {
    union {
	struct passwd	pw;
	struct spwd	sp;
	struct group	gr;
    } d;
    enum {
	t_passwd,
	t_shadow,
	t_group,
	t_error
    } t;
    const char*		name;
    unsigned int	id;
    struct _node*	next;
    char		buf[NSS_BUFLEN_PASSWD];
};

const char*	master_passwd	= DEFAULT_PASSWD_MASTER;
const char*	master_group	= DEFAULT_GROUP_MASTER;
const char*	sys_passwd	= "/etc/passwd";
const char*	sys_shadow	= _PATH_SHADOW;
const char*	sys_group	= "/etc/group";

struct _node*	master_accounts	= NULL;
struct _node*	master_groups	= NULL;
struct _node*	system_accounts	= NULL;
struct _node*	system_shadow	= NULL;
struct _node*	system_groups	= NULL;

int		opt_dryrun	= 0;
int		opt_verbose	= 0;
int		opt_nolock	= 0;
int		opt_sanity	= 0;

int		flag_dirty	= 0;


/* Create an empty list-entry
 */
struct _node* create_node() {
    struct _node*	newnode;

    newnode=(struct _node*)malloc(sizeof(struct _node));
    newnode->name=0;
    newnode->id=0;
    newnode->next=NULL;
    newnode->t=t_error;

    return newnode;
}


void copy_passwd(struct _node* newnode, const struct _node* node) {
    int		idx	= 0;

    assert(node->t==t_passwd);

    newnode->d.pw.pw_uid=node->d.pw.pw_uid;
    newnode->d.pw.pw_gid=node->d.pw.pw_gid;

    newnode->d.pw.pw_name=(newnode->buf+idx);
    idx+=sprintf((newnode->buf+idx), node->d.pw.pw_name)+1;

    newnode->d.pw.pw_passwd=(newnode->buf+idx);
    idx+=sprintf((newnode->buf+idx), node->d.pw.pw_passwd)+1;

    newnode->d.pw.pw_gecos=(newnode->buf+idx);
    idx+=sprintf((newnode->buf+idx), node->d.pw.pw_gecos)+1;

    newnode->d.pw.pw_dir=(newnode->buf+idx);
    idx+=sprintf((newnode->buf+idx), node->d.pw.pw_dir)+1;

    newnode->d.pw.pw_shell=(newnode->buf+idx);
    idx+=sprintf((newnode->buf+idx), node->d.pw.pw_shell)+1;

    if (idx>NSS_BUFLEN_PASSWD) {
	fprintf(stderr, "Aaiieee, we overflowed an entry-buffer, aborting\n");
	exit(100);
    }
}


void copy_shadow(struct _node* newnode, const struct _node* node) {
    int		idx	= 0;

    assert(node->t==t_shadow);

    newnode->d.sp.sp_lstchg=node->d.sp.sp_lstchg;
    newnode->d.sp.sp_min=node->d.sp.sp_min;
    newnode->d.sp.sp_max=node->d.sp.sp_max;
    newnode->d.sp.sp_warn=node->d.sp.sp_warn;
    newnode->d.sp.sp_inact=node->d.sp.sp_inact;
    newnode->d.sp.sp_expire=node->d.sp.sp_expire;

    newnode->d.sp.sp_namp=(newnode->buf+idx);
    idx+=sprintf((newnode->buf+idx), node->d.sp.sp_namp)+1;

    newnode->d.sp.sp_pwdp=(newnode->buf+idx);
    idx+=sprintf((newnode->buf+idx), node->d.sp.sp_pwdp)+1;

    if (idx>NSS_BUFLEN_PASSWD) {
	fprintf(stderr, "Aaiieee, we overflowed an entry-buffer, aborting\n");
	exit(100);
    }
}


void copy_group(struct _node* newnode, const struct _node* node) {
    int		idx	= 0;

    assert(node->t==t_group);

    newnode->d.gr.gr_gid=node->d.gr.gr_gid;

    newnode->d.gr.gr_name=(newnode->buf+idx);
    idx+=sprintf((newnode->buf+idx), node->d.gr.gr_name)+1;

    newnode->d.gr.gr_passwd=(newnode->buf+idx);
    idx+=sprintf((newnode->buf+idx), node->d.gr.gr_passwd)+1;

    newnode->d.gr.gr_name=(newnode->buf+idx);
    idx+=sprintf((newnode->buf+idx), node->d.gr.gr_name)+1;

    /* TODO: properly copy the memberlist. */
    newnode->d.gr.gr_mem=node->d.gr.gr_mem;

    if (idx>NSS_BUFLEN_PASSWD) {
	fprintf(stderr, "Aaiieee, we overflowed an entry-buffer, aborting\n");
	exit(100);
    }
}

/* Make a copy of a list-entry
 */
struct _node* copy_node(const struct _node* node) {
    struct _node*	newnode;

    newnode=create_node();
    newnode->id=node->id;
    newnode->name=node->name;
    newnode->t=node->t;

    switch (newnode->t) {
	case t_passwd:
	    copy_passwd(newnode, node);
	    break;
	case t_shadow:
	    copy_shadow(newnode, node);
	    break;
	case t_group:
	    copy_group(newnode, node);
	    break;
	default:
	    fprintf(stderr, "Internal error: unexpected entrytype %d\n", newnode->t);
	    exit(1);
    }

    return newnode;
}


/* Add a new item to a list
 */
void add_node(struct _node** head, struct _node* node) {
    struct _node*	walk;

    node->next=NULL;

    if (*head==NULL) {
	*head=node;
	return;
    }

    if ((*head)->id > node->id) {
	*head=node;
	return;
    }

    for (walk=*head; walk->next && (walk->next->id <= node->id); walk=walk->next)
	;
    node->next=walk->next;
    walk->next=node;
}


/* Locate an entry with a specific name in the last
 */
struct _node* find_by_name(struct _node* head, const char* name) {
    while (head) {
	if (strcmp(name, head->name)==0)
	    return head;
	head=head->next;
    }

    return NULL;
}


/* Look for an entry in a list, using the name of _entry as the
 * searchkey.
 */
struct _node* find_by_named_entry(struct _node* head, const struct _node* entry) {
    while (head) {
	if (strcmp(entry->name, head->name)==0)
	    return head;
	head=head->next;
    }

    return NULL;
}


/* Look for an entry in a list, using the name of _entry as the
 * searchkey.
 */
struct _node* find_by_id(struct _node* head, unsigned int id) {
    while (head) {
	if (id==head->id)
	    return head;
	head=head->next;
    }

    return NULL;
}


/* Function to scan the list of special users to see if a user has a certain
 * flag set.
 */
int scan_users(unsigned id, unsigned flag) {
    const struct _userinfo*	walk;
    for (walk=specialusers; !((walk->id==0) && (walk->flags==0)); walk++)
	if (walk->id==id)
	    return ((walk->flags&flag)!=0);
    return 0;
}

/* Just for our convenience */
int keephome(unsigned id) { return scan_users(id, FL_KEEPHOME); }
int keepshell(unsigned id) { return scan_users(id, FL_KEEPSHELL); }
int keepgecos(unsigned id) { return scan_users(id, FL_KEEPGECOS); }
int noautoremove(unsigned id) { return scan_users(id, FL_NOAUTOREMOVE); }
int noautoadd(unsigned id) { return scan_users(id, FL_NOAUTOREMOVE); }

/* Function to read passwd database */
int read_passwd(struct _node** list, const char* file) {
    FILE*		input;
    struct _node*	node;
    struct passwd*	result;
    int			success;

    if (opt_verbose)
	printf("Reading passwd from %s\n", file);

    if ((input=fopen(file, "r"))==NULL) {
	fprintf(stderr, "Error opening password file %s: %s\n", file, strerror(errno));
	return 1;
    }

    node=create_node();

    while ((success=fgetpwent_r(input, &(node->d.pw), node->buf, NSS_BUFLEN_PASSWD, &result))==0) {
	node->t=t_passwd;
	node->name=node->d.pw.pw_name;
	if (!node->name)
	    break;
	if (node->name[0]=='+')
	    node->id=INT_MAX;
	else
	    node->id=node->d.pw.pw_uid;
	add_node(list, node);
	node=create_node();
    }

    if ((success!=0) && (errno!=ENOENT)) {
	fprintf(stderr, "Error reading passwd file %s: %s\n", file, strerror(errno));
	return 2;
    }

    free(node);
    fclose(input);

    return 0;
}


/* Function to read group database */
int read_group(struct _node** list, const char* file) {
    FILE*		input;
    struct _node*	node;
    struct group*	result;
    int			success;

    if (opt_verbose)
	printf("Reading group from %s\n", file);

    if ((input=fopen(file, "r"))==NULL) {
	fprintf(stderr, "Error opening group file %s: %s\n", file, strerror(errno));
	return 1;
    }

    node=create_node();

    while ((success=fgetgrent_r(input, &(node->d.gr), node->buf, NSS_BUFLEN_PASSWD, &result))==0) {
	node->t=t_group;
	node->name=node->d.gr.gr_name;
	if (!node->name)
	    break;
	if (node->name[0]=='+')
	    node->id=INT_MAX;
	else
	    node->id=node->d.gr.gr_gid;
	add_node(list, node);
	node=create_node();
    }

    if ((success!=0) && (errno!=ENOENT)) {
	fprintf(stderr, "Error reading shadow file %s: %s\n", file, strerror(errno));
	return 2;
    }
    free(node);
    fclose(input);

    return 0;
}


/* Function to read shadow database */
int read_shadow(struct _node** list, const char* file) {
    FILE*		input;
    struct _node*	node;
    struct spwd*	result;
    int			success;

    if (opt_verbose)
	printf("Reading shadow from %s\n", file);

    if ((input=fopen(file, "r"))==NULL) {
	if (errno!=ENOENT)
	    fprintf(stderr, "Error opening group file %s: %s\n", file, strerror(errno));
	return 1;
    }

    node=create_node();

    while ((success=fgetspent_r(input, &(node->d.sp), node->buf, NSS_BUFLEN_PASSWD, &result))==0) {
	node->t=t_shadow;
	node->id=0;
	node->name=node->d.sp.sp_namp;
	if (!node->name)
	    break;
	add_node(list, node);
	node=create_node();
    }

    if ((success!=0) && (errno!=ENOENT)) {
	fprintf(stderr, "Error reading group file %s: %s\n", file, strerror(errno));
	return 2;
    }

    free(node);
    fclose(input);

    return 0;
}



/* Simple function to usage information
 */
void usage() {
    printf(
	"Usage: update-passwd [OPTION]...\n"
	"\n"
	"  -p, --passwd-master=file  Use file as the master account list\n"
	"  -g, --group-master=file   Use file as the master group list\n"
	"  -P, --passwd=file         Use file as the system passwd file\n"
	"  -S, --shadow=file         Use file as the system shadow file\n"
	"  -G, --group=file          Use file as the system group file\n"
	"  -s, --sanity-check        Only perform sanity-checks\n"
	"  -v, --verbose             Show details about what we are doing (recommended)\n"
	"  -n, --dry-run             Just say what we would do but do nothing\n"
	"  -L, --no-locking          Don't try to lock files\n"
	"  -h, --help                Display this information and exit\n"
	"  -V, --version             Show versionnumer and exit\n"
	"\n"
	" File locations used:\n"
	"   master passwd: %s\n"
	"   master group : %s\n"
	"   system passwd: %s\n"
	"   system shadow: %s\n"
	"   system group : %s\n"
	"\n"
	"Report bugs to the Debian bug tracking system, package \"base-passwd\".\n"
	"\n",
	master_passwd, master_group, sys_passwd, sys_shadow, sys_group);
}

/* Simple function to print our name and version
 */
void version() {
    printf("update-passwd %s\n", VERSION);
}


/* Check if new accounts should be made on the system. Please note we don't
 * add accounts to shadow here; those will be made automatically at a later
 * stage where we verify the contents of the shadow database
 */
void process_new_entries(struct _node** passwd, struct _node* master, const char* descr) {
    while (master) {
	if (find_by_named_entry(*passwd, master)==NULL) {
	    struct _node* newnode;

	    newnode=copy_node(master);
	    add_node(passwd, newnode);
	    flag_dirty++;

	    if (opt_dryrun || opt_verbose)
		printf("Adding %s \"%s\" (%u)\n", descr, newnode->name, newnode->id);
	}
	master=master->next;
    }
}


/* Check if accounts should be removed. Like with process_new_accounts we
 * don't update shadow here since it is verified at a later stage anyway.
 * We will only remove accounts in our range (uids 0-99).
 */
void process_old_entries(struct _node** passwd, struct _node* master, const char* descr) {
    for (;*passwd; passwd=&((*passwd)->next)) {
	if (((*passwd)->id<0) || ((*passwd)->id>99))
	    continue;

	if (noautoremove((*passwd)->id))
	    continue;

	if (find_by_named_entry(master, *passwd)==NULL) {
	    struct _node*	oldnode;

	    oldnode=*passwd;

	    if (opt_dryrun || opt_verbose)
		printf("Removing %s \"%s\" (%u)\n", descr, oldnode->name, oldnode->id);

	    *passwd=(*passwd)->next;
	    free(oldnode);
	    flag_dirty++;
	}
    }
}


/* Check if account-information needs to be updated.
 */
void process_changed_accounts(struct _node* passwd, struct _node* master) {
    for (;passwd; passwd=passwd->next) {
	struct _node*	mc;	/* mastercopy of this account */

	if ((passwd->id<0) || (passwd->id>99))
	    continue;

	mc=find_by_named_entry(master, passwd);
	if (mc==NULL) 
	    continue;

	if (passwd->id!=mc->id) {
	    if (opt_verbose || opt_dryrun)
		printf("Changing uid of %s from %u to %u\n", passwd->name, passwd->id, mc->id);
	    passwd->id=mc->id;
	    passwd->d.pw.pw_uid=mc->d.pw.pw_uid;
	    flag_dirty++;
	}

	if (passwd->d.pw.pw_gid!=mc->d.pw.pw_gid) {
	    if (opt_verbose || opt_dryrun)
		printf("Changing gid of %s from %u to %u\n", passwd->name, passwd->d.pw.pw_gid, mc->d.pw.pw_gid);
	    passwd->d.pw.pw_gid=mc->d.pw.pw_gid;
	    flag_dirty++;
	}

	if (!keepgecos(passwd->id))
	    if ((passwd->d.pw.pw_gecos==NULL) || (strcmp(passwd->d.pw.pw_gecos, mc->d.pw.pw_gecos)!=0)) {
		if (opt_verbose || opt_dryrun)
		    printf("Changing GECOS of %s to \"%s\".\n", passwd->name, mc->d.pw.pw_gecos);
		/* We update the pw_gecos entry of passwd so it now points into the
		 * buffer from mc. This is safe for us, since we know we won't free
		 * the data in mc until after we are done.
		 */
		passwd->d.pw.pw_gecos=mc->d.pw.pw_gecos;
		flag_dirty++;
	    }

	if (!keephome(passwd->id))
	    if ((passwd->d.pw.pw_dir==NULL) || (strcmp(passwd->d.pw.pw_dir, mc->d.pw.pw_dir)!=0)) {
		if (opt_verbose || opt_dryrun)
		    printf("Changing homedirectory of %s to %s\n", passwd->name, mc->d.pw.pw_dir);
		/* We update the pw_dir entry of passwd so it now points into the
		 * buffer from mc. This is safe for us, since we know we won't free
		 * the data in mc until after we are done.
		 */
		passwd->d.pw.pw_dir=mc->d.pw.pw_dir;
		flag_dirty++;
	    }

	if (!keepshell(passwd->id))
	    if ((passwd->d.pw.pw_shell==NULL) || (strcmp(passwd->d.pw.pw_shell, mc->d.pw.pw_shell)!=0)) {
		if (opt_verbose || opt_dryrun)
		    printf("Changing shell of %s to %s\n", passwd->name, mc->d.pw.pw_shell);
		/* We update the pw_shell entry of passwd so it now points into the
		 * buffer from mc. This is safe for us, since we know we won't free
		 * the data in mc until after we are done.
		 */
		passwd->d.pw.pw_shell=mc->d.pw.pw_shell;
		flag_dirty++;
	    }
    }
}


/* Check if account-information needs to be updated.
 */
void process_changed_groups(struct _node* group, struct _node* master) {
    for (;group; group=group->next) {
	struct _node*	mc;	/* mastercopy of this group */

	if ((group->id<0) || (group->id>99))
	    continue;

	mc=find_by_named_entry(master, group);
	if (mc==NULL)
	    continue;

	if (group->id!=mc->id) {
	    if (opt_verbose || opt_dryrun)
		printf("Changing gid of %s from %u to %u\n", group->name, group->id, mc->id);
	    group->id=mc->id;
	    group->d.gr.gr_gid=mc->d.gr.gr_gid;
	    flag_dirty++;
	}
    }
}


int write_passwd(const struct _node* passwd, const char* file) {
    FILE*	output;

    if (opt_verbose)
	printf("Writing passwd-file to %s\n", file);

    if ((output=fopen(file, "wt"))==NULL) {
	fprintf(stderr, "Failed to open passwd-file %s for writing: %s\n",
		file, strerror(errno));
	return 0;
    }

    for (;passwd; passwd=passwd->next) {
	assert(passwd->t==t_passwd);
	if (putpwent(&(passwd->d.pw), output)!=0) {
	    fprintf(stderr, "Error writing passwd-entry: %s\n", strerror(errno));
	    return 0;
	}
    }

    if (fclose(output)!=0) {
	fprintf(stderr, "Error closing passwd-file: %s\n", strerror(errno));
	return 0;
    }

    return 1;
}


int write_shadow(const struct _node* shadow, const char* file) {
    FILE*	output;

    if (opt_verbose)
	printf("Writing shadow-file to %s\n", file);

    if ((output=fopen(file, "wt"))==NULL) {
	fprintf(stderr, "Failed to open shadow-file %s for writing: %s\n",
	       	file, strerror(errno));
	return 0;
    }

    for (;shadow; shadow=shadow->next) {
	assert(shadow->t==t_shadow);
	if (putspent(&(shadow->d.sp), output)!=0) {
	    fprintf(stderr, "Error writing shadow-entry: %s\n", strerror(errno));
	    return 0;
	}
    }

    if (fclose(output)!=0) {
	fprintf(stderr, "Error closing shadow-file: %s\n", strerror(errno));
	return 0;
    }

    return 1;
}


#ifndef HAVE_PUTGRENT
int putgrent(const struct group* g, FILE* f) {
    int idx;
    fprintf(f, "%s:%s:%u:", g->gr_name, g->gr_passwd, g->gr_gid);
    if (g->gr_mem)
	for (idx=0; g->gr_mem[idx]; idx++)
	    fprintf(f, ((idx==0) ? "%s" : ",%s"), g->gr_mem[idx]);
    fprintf(f, "\n");
    return fflush(f);
}
#endif


int write_group(const struct _node* group, const char* file) {
    FILE*	output;

    if (opt_verbose)
	printf("Writing group-file to %s\n", file);

    if ((output=fopen(file, "wt"))==NULL) {
	fprintf(stderr, "Failed to open group-file %s for writing: %s\n",
		file, strerror(errno));
	return 0;
    }

    for (;group; group=group->next) {
	assert(group->t==t_group);
	if (putgrent(&(group->d.gr), output)!=0) {
	    fprintf(stderr, "Error writing group-entry: %s\n", strerror(errno));
	    return 0;
	}
    }

    if (fclose(output)!=0) {
	fprintf(stderr, "Error closing group-file: %s\n", strerror(errno));
	return 0;
    }

    return 1;
}


/* Unlink a file and print an error on failure.
 */
int unlink_file(const char* file) {
    if (unlink(file)!=0) {
	fprintf(stderr, "Error unlinking %s: %s\n", file, strerror(errno));
	return 0;
    }

    return 1;
}


/* Rename a file and print an error on failure.
 */
int rename_file(const char* source, const char* target) {
    if (rename(source, target)!=0) {
	fprintf(stderr, "Error renaming %s to %s: %s\n",
		source, target, strerror(errno));
	return 0;
    }

    return 1;
}


/* Copy the filemodes from one file to another
 */

int copy_filemodes(const char* source, const char* target) {
    struct stat		st;

    if (lstat(source, &st)!=0) {
	fprintf(stderr, "Error lstating %s: %s\n", source, strerror(errno));
	return 0;
    }

    if (chmod(target, st.st_mode)!=0) {
	fprintf(stderr, "Error chmoding %s: %s\n", source, strerror(errno));
	return 0;
    }

    if (lchown(target, st.st_uid, st.st_gid)!=0)
	/* Hmm, this failed. Lets try a normal chown in case we
	 * are running on a kernel that doesn't support lchown
	 */
	if (errno==ENOSYS) {
	    struct stat           tst;

	    if (lstat (target, &tst)!=0) {
		fprintf (stderr, "Error lstating %s: %s\n",
			target, strerror(errno));
		return 0;
	    }

	    if (!S_ISLNK (tst.st_mode) &&
		    chown (target, st.st_uid, st.st_gid) != 0) {
		fprintf(stderr, "Error lchowning %s: %s\n",
			source, strerror(errno));
		return 0;
	    }
	} else {
	    fprintf(stderr, "Error lchowning %s: %s\n",
		    source, strerror(errno));
	    return 0;
	}

    return 1;
}


/* Try to replace a file as safely as possible. If we fail unlink the
 * new copy, since it's useless anyway.
 */
int put_file_in_place(const char* source, const char* target) {
    char	uf[PATH_MAX];

    if (opt_verbose)
	printf("Replacing \"%s\" with \"%s\"\n", target, source);

    snprintf(uf, PATH_MAX, "%s%s", target, UNLINK_EXTENSION);

    umask(0077);

    if (!rename_file(target, uf)) {
	unlink_file(source);
	return 0;
    }

    if (!rename_file(source, target)) {
	rename_file(uf, target);
	return 0;
    }

    if (!copy_filemodes(uf, target)) {
	unlink_file(uf);
	return 0;
    }

    return unlink_file(uf);
}


/* Rewrite the account-database if we made any changes
 */
int commit_files() {
    char	wf[PATH_MAX];

    if (!flag_dirty) {
	if (opt_verbose)
	    printf("No changes made, doing nothing\n");
	return 1;
    }

    if (opt_dryrun) {
	printf("Would commit %d changes\n", flag_dirty);
	return 1;
    }

    printf("%d changes have been made, rewriting files\n", flag_dirty);

    snprintf(wf, PATH_MAX, "%s%s", sys_passwd, WRITE_EXTENSION);
    if (!write_passwd(system_accounts, wf))
	return 0;
    if (!put_file_in_place(wf, sys_passwd))
	return 0;

    if (system_shadow!=NULL) {
	snprintf(wf, PATH_MAX, "%s%s", sys_shadow, WRITE_EXTENSION);
	if (!write_shadow(system_shadow, wf))
	    return 0;
	if (!put_file_in_place(wf, sys_shadow))
	    return 0;
    }

    snprintf(wf, PATH_MAX, "%s%s", sys_group, WRITE_EXTENSION);
    if (!write_group(system_groups, wf))
	return 0;
    if (!put_file_in_place(wf, sys_group))
	return 0;

    return 1;
}


/* Try to lock the account database
 */
int lock_files() {
    if (lckpwdf()!=0) {
	fprintf(stderr, "Error locking files: %s\n", strerror(errno));
	return 0;
    }

    return 1;
}


/* Try to unlock the account database
 */
int unlock_files() {
    if (ulckpwdf()!=0) {
	fprintf(stderr, "Error unlocking files: %s\n", strerror(errno));
	return 0;
    }

    return 1;
}


/* I don't need to say what main is for, do I?
 */
int main(int argc, char** argv) {
    int		optc;
    int		opt_index;

    struct option const options[] = {
	{ "passwd-master",	required_argument,	0,	'p' },
	{ "group-master",	required_argument,	0,	'g' },
	{ "passwd",		required_argument,	0,	'P' },
	{ "shadow",		required_argument,	0,	'S' },
	{ "group",		required_argument,	0,	'G' },
	{ "sanity-check",	no_argument,		0,	's' },
	{ "verbose",		no_argument,		0,	'v' },
	{ "dry-run",		no_argument,		0,	'n' },
	{ "help",		no_argument,		0,	'h' },
	{ "version",		no_argument,		0,	'V' },
	{ 0, 0, 0, 0 }
    };
    
    while ((optc=getopt_long(argc, argv, "g:p:G:P:S:snvLhV", options, &opt_index))!=-1)
	switch (optc)  {
	    case 'p':
		master_passwd=optarg;
		break;
	    case 'g':
		master_group=optarg;
		break;
	    case 'P':
		sys_passwd=optarg;
		break;
	    case 'S':
		sys_shadow=optarg;
		break;
	    case 'G':
		sys_group=optarg;
		break;
	    case 'v':
		opt_verbose++;
		break;
	    case 's':
		opt_sanity=1;
		break;
	    case 'n':
		opt_dryrun=1;
		break;
	    case 'L':
		opt_nolock=1;
		break;
	    case 'h':
		usage();
		return 0;
	    case 'V':
		version();
		return 0;
	    default:
		fprintf(stderr, "Internal error: getopt_long returned unexpected value \'%c\'\n", optc);
		return 1;
	}

    if (read_passwd(&master_accounts, master_passwd)!=0)
	return 2;

    if (read_group(&master_groups, master_group)!=0)
	return 2;

    if (read_passwd(&system_accounts, sys_passwd)!=0)
	return 2;

    /* Only abort on a readerror */
    if ((read_shadow(&system_shadow, sys_shadow)!=0) && (errno!=ENOENT))
	return 2;

    if (read_group(&system_groups, sys_group)!=0)
	return 2;

    process_new_entries(&system_accounts, master_accounts, "user");
    process_old_entries(&system_accounts, master_accounts, "user");
    process_changed_accounts(system_accounts, master_accounts);

    process_new_entries(&system_groups, master_groups, "group");
    process_old_entries(&system_groups, master_groups, "group");
    process_changed_groups(system_groups, master_groups);

    if (opt_sanity)
	return 0;

    if (!opt_nolock && !opt_dryrun)
	if (!lock_files())
	    return 3;

    if (!commit_files()) {
	unlock_files();
	return 4;
    }

    if (!opt_nolock && !opt_dryrun)
	if (!unlock_files())
	    return 5;

    if (opt_dryrun)
	return flag_dirty;
    else
	return 0;
}

