/* update-passwd - Safely update /etc/passwd and /etc/group databases
   Copyright (C) 1997 Software in the Public Interest.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. */

/* update-passwd was written to handle "automagic" updates of the critical
   0-99 UID entries in /etc/passwd and /etc/group.  The Debian base-passwd
   package contains {passwd,group}.master, which are used as references
   when editing the active files.

   The program makes one assumption about the structure of the
   passwd/group files; it expects to find the first 100 entries at the
   start of the file, in numerical order.  */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>

#include <pwd.h>
#include <grp.h>
#include <shadow.h>

#define VERSION "0.5"

#define DEFAULT_PASSWD_MASTER "/usr/share/base-passwd/passwd.master"
#define DEFAULT_GROUP_MASTER "/usr/share/base-passwd/group.master"
#define PASSWD_NEW "/etc/passwd.new"
#define GROUP_NEW "/etc/group.new"
#define PASSWD_BAK "/etc/passwd.bak"
#define GROUP_BAK "/etc/group.bak"

/* If nonzero, don't print any action messages. */
int be_quiet = 0;

/* If nonzero, display help information. */
int show_help = 0;

/* If nonzero, display version information. */
int show_version = 0;

#ifdef MISERABLE_FTP_HACK
/* If nonzero, be on alert for bogus ftp user at uid 11. */
int ftp_hack = 0;

/* Preserve ftp user settings. */
struct passwd ftp_user;
char ftp_string[1024];
#endif

/* Name of passwd.master file to be used. */
char *pmaster_name = NULL;

/* Name of group.master file to be used. */
char *gmaster_name = NULL;

/* Simple wrapper for handling errors. */
void error(const char *str) {
    fprintf(stderr, "%s: %s\n", str, strerror(errno));
}

/* Get a password file entry from f into rec, or die gracefully. */
int get_pwd_entry(FILE *f, const char *name, struct passwd *rec, char *buf,
	FILE *n) {
    struct passwd *result;

    if (fgetpwent_r(f, rec, buf, 1024, &result)) {
	ulckpwdf();
	if (feof(f))
	    fprintf(stderr, "%s: Unexpected EOF\n", name);
	else
	    error(name);
	fclose(n); unlink(PASSWD_NEW);
	return -1;
    }

    return 0;
}

/* Get a group file entry from f into rec, or die gracefully. */
int get_grp_entry(FILE *f, const char *name, struct group *rec, char *buf,
	FILE *n) {
    struct group *result;

    if (fgetgrent_r(f, rec, buf, 1024, &result)) {
	if (feof(f))
	    fprintf(stderr, "%s: Unexpected EOF\n", name);
	else
	    error(name);
	fclose(n); unlink(GROUP_NEW);
	return -1;
    }

    return 0;
}

/* Write the password file entry from rec into f, or die gracefully. */
int write_pwd_entry(FILE *f, struct passwd *rec) {
    if (fprintf(f, "%s:%s:%u:%u:%s:%s:%s\n", rec->pw_name, rec->pw_passwd,
		rec->pw_uid, rec->pw_gid, rec->pw_gecos, rec->pw_dir,
		rec->pw_shell) == -1) {
	ulckpwdf();
	error(PASSWD_NEW);
	fclose(f); unlink(PASSWD_NEW);
	return -1;
    }

    return 0;
}

/* Write the group file entry from rec into f, or die gracefully. */
int write_grp_entry(FILE *f, struct group *rec) {
    int i = 0;

    if (fprintf(f, "%s:*:%u:", rec->gr_name, rec->gr_gid) == -1) {
	error(GROUP_NEW);
	fclose(f); unlink(GROUP_NEW);
	return -1;
    }

    while(rec->gr_mem[i] != NULL) {
	fprintf(f, "%s", rec->gr_mem[i]);
	i++;
	if (rec->gr_mem[i] != NULL) fprintf(f, ",");
    }

    if (fprintf(f, "\n") == -1) {
	error(GROUP_NEW);
	fclose(f); unlink(GROUP_NEW);
	return -1;
    }

    return 0;
}

/* This function makes sure the following conditions are true:  that the
   passwd/group files have id's 0-99 in numerical order, and there are no
   id's of those values hidden later in the file. */
int sanity_check() {
    struct passwd *pwd;
    struct group *grp;
    int count = 0;

    setpwent();

    while ((pwd = getpwent()) != NULL) {
	if (count > pwd->pw_uid) {
	    fprintf(stderr, "WARNING: /etc/passwd fails sanity check!\n");
	    fprintf(stderr, "User \"%s\" is uid %d but after gids >= 100\n", pwd->pw_name, pwd->pw_uid);
	    return -1;
	}
	if (pwd->pw_uid < 100) count = pwd->pw_uid;
    }

    endpwent();
    count = 0;
    setgrent();

    while ((grp = getgrent()) != NULL) {
	if (count > grp->gr_gid) {
	    fprintf(stderr, "WARNING: /etc/group fails sanity check!\n");
	    fprintf(stderr, "Group \"%s\" is gid %d but after gids >= 100\n", grp->gr_name, grp->gr_gid);
	    return -1;
	}
	if (grp->gr_gid < 100) count = grp->gr_gid;
    }

    endgrent();
    return 0;
}

/* No point in being stingy. */
char sys_buf[1024], master_buf[1024];

/* Generate a new passwd file, merging in changes from the master file.  If
   changes have been made, backup and replace the current /etc/passwd. */
int compare_passwd() {
    FILE *pwd, *master, *new;
    struct passwd pwd_rec, master_rec;
    int changes = 0;

    if (lckpwdf()) {
	error("Unable to lock /etc/passwd");
	return -1;
    }

    if ((pwd = fopen("/etc/passwd", "r")) == NULL) {
	ulckpwdf();
	error("Unable to open /etc/passwd");
	return -1;
    }
    if ((master = fopen(pmaster_name, "r")) == NULL) {
	ulckpwdf();
	error("Unable to open password master file");
	return -1;
    }
    if ((new = fopen(PASSWD_NEW, "w")) == NULL) {
	ulckpwdf();
	error("Unable to open " PASSWD_NEW);
	return -1;
    }

    /* Take first line from each file. */
    if (get_pwd_entry(pwd, "/etc/passwd", &pwd_rec, sys_buf, new))
	return -1;
    if (get_pwd_entry(master, pmaster_name, &master_rec, master_buf, new))
	return -1;

    do {
#ifdef MISERABLE_FTP_HACK
	/* If this is the ftp user, preserve all information. */
	if (ftp_hack && pwd_rec.pw_uid == 11) {
	    char *p = ftp_string;

	    ftp_user.pw_uid = 999;
	    ftp_user.pw_gid = pwd_rec.pw_gid;
	    strcpy(p, pwd_rec.pw_name);
	    ftp_user.pw_name = p;
	    p += (strlen(p) + 1);
	    ftp_user.pw_passwd = p;
	    strcpy(p, pwd_rec.pw_passwd);
	    p += (strlen(p) + 1);
	    ftp_user.pw_gecos = p;
	    strcpy(p, pwd_rec.pw_gecos);
	    p += (strlen(p) + 1);
	    ftp_user.pw_dir = p;
	    strcpy(p, pwd_rec.pw_dir);
	    p += (strlen(p) + 1);
	    ftp_user.pw_shell = p;
	    strcpy(p, pwd_rec.pw_shell);
	}
#endif

	/* Case 1: A UID has been added to passwd.master. */
	if (pwd_rec.pw_uid > master_rec.pw_uid) {
	    if (!be_quiet) printf("Adding new user \"%s\" (%u).\n",
		    master_rec.pw_name, master_rec.pw_uid);
	    if (write_pwd_entry(new, &master_rec))
		return -1;
	    if (get_pwd_entry(master, pmaster_name, &master_rec, master_buf, new))
		return -1;
	    changes++;
	}

	/* Case 2: A UID has been removed from passwd.master. */
	else if (pwd_rec.pw_uid < master_rec.pw_uid) {
	    if (!be_quiet) printf("Removing user \"%s\" (%u).\n",
		    pwd_rec.pw_name, pwd_rec.pw_uid);
	    if (get_pwd_entry(pwd, "/etc/passwd", &pwd_rec, sys_buf, new))
		return -1;
	    changes++;
	}

	/* Case 3: Check for differences, but don't change root. */
	else {
	    if (pwd_rec.pw_uid) {
		if (strcmp(pwd_rec.pw_name, master_rec.pw_name)) {
		    if (!be_quiet) printf("Changed uid %u from \"%s\" to \"%s\".\n",
			    pwd_rec.pw_uid, pwd_rec.pw_name,
			    master_rec.pw_name);
		    pwd_rec.pw_name = master_rec.pw_name;
		    changes++;
		}
		if (pwd_rec.pw_gid != master_rec.pw_gid) {
		    if (!be_quiet) printf("Changed gid for \"%s\" from %u to %u.\n",
			    pwd_rec.pw_name, pwd_rec.pw_gid,
			    master_rec.pw_gid);
		    pwd_rec.pw_gid = master_rec.pw_gid;
		    changes++;
		}
		if (strcmp(pwd_rec.pw_gecos, master_rec.pw_gecos)) {
		    if (!be_quiet) printf("Changed description of \"%s\" to \"%s\".\n",
			    pwd_rec.pw_name, master_rec.pw_gecos);
		    pwd_rec.pw_gecos = master_rec.pw_gecos;
		    changes++;
		}
		if (strcmp(pwd_rec.pw_dir, master_rec.pw_dir)) {
		    if (!be_quiet) printf("Changed directory of \"%s\" to \"%s\".\n",
			    pwd_rec.pw_name, master_rec.pw_dir);
		    pwd_rec.pw_dir = master_rec.pw_dir;
		    changes++;
		}
		if (strcmp(pwd_rec.pw_shell, master_rec.pw_shell)) {
		    if (!be_quiet) printf("Changed shell of \"%s\" to \"%s\".\n",
			    pwd_rec.pw_name, master_rec.pw_shell);
		    pwd_rec.pw_shell = master_rec.pw_shell;
		    changes++;
		}
	    }
	    if (write_pwd_entry(new, &pwd_rec)) return -1;

	    if (get_pwd_entry(pwd, "/etc/passwd", &pwd_rec, sys_buf, new))
		return -1;
	    if (get_pwd_entry(master, pmaster_name, &master_rec, master_buf, new))
		return -1;

	}

    } while (pwd_rec.pw_uid < 100);

    if (write_pwd_entry(new, &pwd_rec)) return -1;
    fclose(master);

    /* If nothing's been changed, just stop at this point. */
    if (!changes) {
	if (!be_quiet) printf("No changes to /etc/passwd.\n");
	ulckpwdf();
	fclose(pwd); fclose(new); unlink(PASSWD_NEW);
	return 0;
    }

    /* Everything below this shouldn't need changing.  Therefore, we simply
       shovel the rest of /etc/passwd through. */
    while (!feof(pwd)) {
	int count;

	if ((count = fread(sys_buf, 1, 1024, pwd)) == 0 && !feof(pwd)) {
	    ulckpwdf();
	    error("/etc/passwd");
	    fclose(new); unlink(PASSWD_NEW);
	    return -1;
	}
	if (fwrite(sys_buf, 1, count, new) < count) {
	    ulckpwdf();
	    error(PASSWD_NEW);
	    fclose(new); unlink(PASSWD_NEW);
	    return -1;
	}
    }

#ifdef MISERABLE_FTP_HACK
    if (ftp_hack && ftp_user.pw_uid == 999) {
	ftp_user.pw_name = ftp_string;  /* This vanishes; why? */
	if (write_pwd_entry(new, &ftp_user)) return -1;
    }
#endif

    fclose(pwd); fclose(new);

    /* Enforce correct permissions on new passwd file.  This should be right
       by default, but you never know... */
    if (chown(PASSWD_NEW, 0, 0) ||
	    chmod(PASSWD_NEW, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) {
	ulckpwdf();
	error(PASSWD_NEW);
	unlink(PASSWD_NEW);
	return -1;
    }

    /* Back up and replace passwd in reasonably safe manner. */
    unlink(PASSWD_BAK);
    if (link("/etc/passwd", PASSWD_BAK)) {
	ulckpwdf();
	error("Unable to back up /etc/passwd");
	return -1;
    }
    if (rename(PASSWD_NEW, "/etc/passwd")) {
	ulckpwdf();
	error("Unable to replace /etc/passwd");
	return -1;
    }

    ulckpwdf();
    return 0;
}

/* A nearly identical function to update /etc/group, brought to you by
   the miracle of cut-n-paste programming. */
int compare_group() {
    FILE *grp, *master, *new;
    struct group grp_rec, master_rec;
    int changes = 0;

    if ((grp = fopen("/etc/group", "r")) == NULL) {
	error("Unable to open /etc/group");
	return -1;
    }
    if ((master = fopen(gmaster_name, "r")) == NULL) {
	error("Unable to open group master file");
	return -1;
    }
    if ((new = fopen(GROUP_NEW, "w")) == NULL) {
	error("Unable to open " GROUP_NEW);
	return -1;
    }

    /* Take first line from each file. */
    if (get_grp_entry(grp, "/etc/group", &grp_rec, sys_buf, new))
	return -1;
    if (get_grp_entry(master, gmaster_name, &master_rec, master_buf, new))
	return -1;

    do {

	/* Case 1: A GID has been added to group.master. */
	if (grp_rec.gr_gid > master_rec.gr_gid) {
	    if (!be_quiet) printf("Adding new group \"%s\" (%u).\n",
		    master_rec.gr_name, master_rec.gr_gid);
	    if (write_grp_entry(new, &master_rec)) return -1;
	    if (get_grp_entry(master, gmaster_name, &master_rec, master_buf, new))
		return -1;
	    changes++;
	}

	/* Case 2: A GID has been removed from group.master. */
	else if (grp_rec.gr_gid < master_rec.gr_gid) {
	    if (!be_quiet) printf("Removing group \"%s\" (%u).\n",
		    grp_rec.gr_name, grp_rec.gr_gid);
	    if (get_grp_entry(grp, "/etc/group", &grp_rec, sys_buf, new))
		return -1;
	    changes++;
	}

	/* Case 3: Check for differences. */
	else {
	    if (strcmp(grp_rec.gr_name, master_rec.gr_name)) {
		if (!be_quiet) printf("Changed gid %u from \"%s\" to \"%s\".\n",
			grp_rec.gr_gid, grp_rec.gr_name,
			master_rec.gr_name);
		grp_rec.gr_name = master_rec.gr_name;
		changes++;
	    }
	    if (write_grp_entry(new, &grp_rec)) return -1;

	    if (get_grp_entry(grp, "/etc/group", &grp_rec, sys_buf, new))
		return -1;
	    if (get_grp_entry(master, gmaster_name, &master_rec, master_buf, new))
		return -1;

	}

    } while (grp_rec.gr_gid < 100);

    if (write_grp_entry(new, &grp_rec)) return -1;
    fclose(master);

    /* If nothing's been changed, just stop at this point. */
    if (!changes) {
	if (!be_quiet) printf("No changes to /etc/group.\n");
	fclose(grp); fclose(new); unlink(GROUP_NEW);
	return 0;
    }

    /* Everything below this shouldn't need changing.  Therefore, we simply
       shovel the rest of /etc/group through. */
    while (!feof(grp)) {
	int count;

	if ((count = fread(sys_buf, 1, 1024, grp)) == 0 && !feof(grp)) {
	    error("/etc/group");
	    fclose(new); unlink(GROUP_NEW);
	    return -1;
	}
	if (fwrite(sys_buf, 1, count, new) < count) {
	    error(GROUP_NEW);
	    fclose(new); unlink(GROUP_NEW);
	    return -1;
	}
    }
    fclose(grp); fclose(new);

    /* Enforce correct permissions on new group file.  This should be right
       by default, but you never know... */
    if (chown(GROUP_NEW, 0, 0) ||
	    chmod(GROUP_NEW, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) {
	error(GROUP_NEW);
	unlink(GROUP_NEW);
	return -1;
    }

    /* Back up and replace group in reasonably safe manner. */
    unlink(GROUP_BAK);
    if (link("/etc/group", GROUP_BAK)) {
	error("Unable to back up /etc/group");
	return -1;
    }
    if (rename(GROUP_NEW, "/etc/group")) {
	error("Unable to replace /etc/group");
	return -1;
    }

    return 0;
}

static void usage() {
  printf("Usage: update-passwd [OPTION]...\n"
	 "\n"
	 "  -g, --group-master=FILE  Use FILE as the master group list\n"
	 "  -p, --passwd-master=FILE Use FILE as the master passwd list\n"
	 "  -q, --quiet              don't print action messages\n"
	 "  -s, --sanity-check       Make sure /etc/passwd and group are okay\n"
	 "      --help               display this help and exit\n"
	 "      --version            output version information and exit\n\n");
  printf("If passwd-master is not specified, use %s.\n"
	 "If group-master is not specified, use %s.\n\n",
	 DEFAULT_PASSWD_MASTER, DEFAULT_GROUP_MASTER);
  printf("Report bugs to the Debian bug tracking system, package \"base-passwd\".");
  exit(0);
}


static struct option const long_options[] = {
    {"group-master",	required_argument,	0,		'g' },
    {"passwd-master",	required_argument,	0,		'p' },
    {"quiet",		no_argument,		0,		'q' },
    {"sanity-check",	no_argument,		0,		's' },
#ifdef MISERABLE_FTP_HACK
    {"move-ftp",	no_argument,		&ftp_hack,	1 },
#endif
    {"help",		no_argument,		&show_help,	1 },
    {"version",		no_argument,		&show_version,	1 },
    {0, 0, 0, 0}
};


int main(int argc, char **argv) {
    int	optc;
    int	opt_index = 0;
    int	do_sanity = 0;

    while ((optc = getopt_long(argc, argv, "g:p:qs", long_options, &opt_index)) != -1) {
	switch (optc) {
	    case 'g':
		gmaster_name = optarg;
		break;

	    case 'p':
		pmaster_name = optarg;
		break;

	    case 'q':
		be_quiet = 1;
		break;

	    case 's':
		do_sanity = 1;

	    default:
		break;
	}
    }

    if (show_help)
	usage();

    if (show_version) {
	printf("update-passwd " VERSION "\n");
	exit(0);
    }

    if (pmaster_name == NULL) pmaster_name = DEFAULT_PASSWD_MASTER;
    if (gmaster_name == NULL) gmaster_name = DEFAULT_GROUP_MASTER;

    if (sanity_check())
	exit(-1);
    else
	if (do_sanity)
	    exit(0);

    if (compare_passwd())
	exit(-1);
    if (compare_group())
	exit(-1);

    return 0;
}

