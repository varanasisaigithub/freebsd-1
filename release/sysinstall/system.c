/*
 * The new sysinstall program.
 *
 * This is probably the last program in the `sysinstall' line - the next
 * generation being essentially a complete rewrite.
 *
 * $Id: system.c,v 1.44.2.7 1995/10/16 15:14:26 jkh Exp $
 *
 * Jordan Hubbard
 *
 * My contributions are in the public domain.
 *
 * Parts of this file are also blatently stolen from Poul-Henning Kamp's
 * previous version of sysinstall, and as such fall under his "BEERWARE license"
 * so buy him a beer if you like it!  Buy him a beer for me, too!
 * Heck, get him completely drunk and send me pictures! :-)
 */

#include "sysinstall.h"
#include <signal.h>
#include <sys/reboot.h>
#include <machine/console.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

/*
 * Handle interrupt signals - this probably won't work in all cases
 * due to our having bogotified the internal state of dialog or curses,
 * but we'll give it a try.
 */
static void
handle_intr(int sig)
{
    if (!msgYesNo("Are you sure you want to abort the installation?"))
	systemShutdown();
}

/* Initialize system defaults */
void
systemInitialize(int argc, char **argv)
{
    int i;

    signal(SIGINT, SIG_IGN);
    globalsInit();

    /* Are we running as init? */
    if (getpid() == 1) {
	setsid();
	close(0); open("/dev/ttyv0", O_RDWR);
	close(1); dup(0);
	close(2); dup(0);
	printf("%s running as init\n", argv[0]);

	i = ioctl(0, TIOCSCTTY, (char *)NULL);
	setlogin("root");
	setenv("PATH", "/stand:/bin:/sbin:/usr/sbin:/usr/bin:/mnt/bin:/mnt/sbin:/mnt/usr/sbin:/mnt/usr/bin:/usr/X11R6/bin", 1);
	setbuf(stdin, 0);
	setbuf(stderr, 0);
    }

    if (set_termcap() == -1) {
	printf("Can't find terminal entry\n");
	exit(-1);
    }

    /* XXX - libdialog has particularly bad return value checking */
    init_dialog();
    /* If we haven't crashed I guess dialog is running ! */
    DialogActive = TRUE;

    signal(SIGINT, handle_intr);
}

/* Close down and prepare to exit */
void
systemShutdown(void)
{
    if (DialogActive) {
	end_dialog();
	DialogActive = FALSE;
    }
    /* REALLY exit! */
    if (RunningAsInit) {
	/* Put the console back */
	ioctl(0, VT_ACTIVATE, 2);
	reboot(0);
    }
    else
	exit(1);
}

/* Run some general command */
int
systemExecute(char *command)
{
    int status;

    dialog_clear();
    dialog_update();
    end_dialog();
    DialogActive = FALSE;
    status = system(command);
    DialogActive = TRUE;
    dialog_clear();
    dialog_update();
    return status;
}

/* Display a file in a filebox */
int
systemDisplayFile(char *file)
{
    char *fname = NULL;
    char buf[FILENAME_MAX];
    WINDOW *w;

    fname = systemHelpFile(file, buf);
    if (!fname) {
	snprintf(buf, FILENAME_MAX, "The %s file is not provided on this particular floppy image.", file);
	use_helpfile(NULL);
	use_helpline(NULL);
	w = dupwin(newscr);
	dialog_mesgbox("Sorry!", buf, -1, -1);
	touchwin(w);
	wrefresh(w);
	delwin(w);
	return 1;
    }
    else {
	use_helpfile(NULL);
	use_helpline(NULL);
	w = dupwin(newscr);
	dialog_textbox(file, fname, LINES, COLS);
	touchwin(w);
	wrefresh(w);
	delwin(w);
    }
    return 0;
}

char *
systemHelpFile(char *file, char *buf)
{
    if (!file)
	return NULL;

    snprintf(buf, FILENAME_MAX, "/stand/help/%s.hlp", file);
    if (file_readable(buf)) 
	return buf;
    return NULL;
}

void
systemChangeTerminal(char *color, const u_char c_term[],
		     char *mono, const u_char m_term[])
{
    extern void init_acs(void);

    if (OnVTY) {
	if (ColorDisplay) {
	    setenv("TERM", color, 1);
	    setenv("TERMCAP", c_term, 1);
	    reset_shell_mode();
	    setterm(color);
	    init_acs();
	    cbreak(); noecho();
	}
	else {
	    setenv("TERM", mono, 1);
	    setenv("TERMCAP", m_term, 1);
	    reset_shell_mode();
	    setterm(mono);
	    init_acs();
	    cbreak(); noecho();
	}
    }
    clear();
    refresh();
    dialog_clear();
}

int
vsystem(char *fmt, ...)
{
    va_list args;
    int pstat;
    pid_t pid;
    int omask;
    sig_t intsave, quitsave;
    char *cmd,*p;
    int i,magic=0;

    cmd = (char *)malloc(FILENAME_MAX);
    cmd[0] = '\0';
    va_start(args, fmt);
    vsnprintf(cmd, FILENAME_MAX, fmt, args);
    va_end(args);

    /* Find out if this command needs the wizardry of the shell */
    for (p="<>|'`=\"()" ; *p; p++)
	if (strchr(cmd, *p))
	    magic++;
    omask = sigblock(sigmask(SIGCHLD));
    if (isDebug())
	msgDebug("Executing command `%s' (Magic=%d)\n", cmd, magic);
    switch(pid = fork()) {
    case -1:			/* error */
	(void)sigsetmask(omask);
	i = 127;

    case 0:				/* child */
	(void)sigsetmask(omask);
	if (DebugFD != -1) {
	    if (OnVTY && isDebug())
		msgInfo("Command output is on debugging screen - type ALT-F2 to see it");
	    dup2(DebugFD, 0);
	    dup2(DebugFD, 1);
	    dup2(DebugFD, 2);
	}
#ifdef NOT_A_GOOD_IDEA_CRUNCHED_BINARY
	if (magic) {
	    char *argv[100];
	    i = 0;
	    argv[i++] = "crunch";
	    argv[i++] = "sh";
	    argv[i++] = "-c";
	    argv[i++] = cmd;
	    argv[i] = 0;
	    exit(crunched_main(i,argv));
	} else {
	    char *argv[100];
	    i = 0;
	    argv[i++] = "crunch";
	    while (cmd && *cmd) {
		argv[i] = strsep(&cmd," \t");
		if (*argv[i])
		    i++;
	    }
	    argv[i] = 0;
	    if (crunched_here(argv[1]))
		exit(crunched_main(i,argv));
	    else
		execvp(argv[1],argv+1);
	    kill(getpid(),9);
	}
#else /* !CRUNCHED_BINARY */
	execl("/stand/sh", "sh", "-c", cmd, (char *)NULL);
	kill(getpid(),9);
#endif /* CRUNCHED_BINARY */
    }
    intsave = signal(SIGINT, SIG_IGN);
    quitsave = signal(SIGQUIT, SIG_IGN);
    pid = waitpid(pid, &pstat, 0);
    (void)sigsetmask(omask);
    (void)signal(SIGINT, intsave);
    (void)signal(SIGQUIT, quitsave);
    i = (pid == -1) ? -1 : WEXITSTATUS(pstat);
    if (isDebug())
	msgDebug("Command `%s' returns status of %d\n", cmd, i);
    free(cmd);
    return i;
}

/*
 * This is called from the main menu.  Try to find a copy of Lynx from somewhere
 * and fire it up on the first copy of the handbook we can find.
 */
int
docBrowser(char *junk)
{
    char *browser = variable_get(BROWSER_PACKAGE);
 
    /* Make sure we were started at a reasonable time */
    if (!variable_get(SYSTEM_INSTALLED)) {
	msgConfirm("Sorry, it's not possible to invoke the browser until the system\n"
		   "is installed completely enough to support a copy of %s.", browser);
	return RET_FAIL;
    }

    if (!mediaVerify())
	return RET_FAIL;

    /* First, make sure we have whatever browser we've chosen is here */
    if (package_extract(mediaDevice, browser) != RET_SUCCESS) {
	msgConfirm("Unable to install the %s HTML browser package.  You may\n"
		   "wish to verify that your media is configured correctly and\n"
		   "try again.", browser);
	return RET_FAIL;
    }
    if (!file_executable(variable_get(BROWSER_BINARY))) {
	if (!msgYesNo("Hmmm.  The %s package claims to have installed, but I can't\n"
		      "find its binary in %s!  You may wish to try a different\n"
		      "location to load the package from (go to Media menu) and see if that\n"
		      "makes a difference.\n\n"
		      "I suggest that we remove the version that was extracted since it does\n"
		      "not appear to be correct.   Would you like me to do that now?"))
	    vsystem("pkg_delete %s %s", !strcmp(variable_get(CPIO_VERBOSITY_LEVEL), "high") ? "-v" : "", browser);
	return RET_FAIL;
    }

    /* Run browser on the appropriate doc */
    dmenuOpenSimple(&MenuHTMLDoc);
    return RET_SUCCESS;
}

/* Specify which package to load for a browser */
int
docSelectBrowserPkg(char *str)
{
    return variable_get_value(BROWSER_PACKAGE, "Please specify the name of the HTML browser package:");
}

/* Specify which binary to load for a browser */
int
docSelectBrowserBin(char *str)
{
    return variable_get_value(BROWSER_BINARY, "Please specify a full pathname to the HTML browser binary:");
}

/* Try to show one of the documents requested from the HTML doc menu */
int
docShowDocument(char *str)
{
    char *browser = variable_get(BROWSER_BINARY);

    if (!file_executable(browser)) {
	msgConfirm("Can't find the browser in %s!  Please ensure that it's\n"
		   "properly set in the Options editor.", browser);
	return RET_FAIL;
    }
    if (!strcmp(str, "Home"))
	vsystem("%s http://www.freebsd.org", browser);
    else if (!strcmp(str, "Other")) {
    }
    else {
	char target[512];

	sprintf(target, "/usr/share/doc/%s/%s.html", str, str);
	if (file_readable(target))
	    vsystem("%s file:%s", browser, target);
	else
	    vsystem("%s http://www.freebsd.org/%s");
    }
}

