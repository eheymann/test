#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MAX 100

int main() {

	int uid, gid;
	char jailDir [MAX], prog [MAX];
	char argv[MAX];
	int fd;

	printf ("uid, gid, jailDir, prog, arg\n");
	scanf ("%d%d%s%s%s", &uid, &gid, jailDir, prog, argv);
	fd = open ("logfile", O_WRONLY);
	if (fd < 0) {
		printf ("open ERROR");
		exit (1);
	}
	
	if (uid == 0 || gid == 0) 
		exit (1);	
	chroot (jailDir);

	setuid (uid);
	setgid (gid);

	printf ("execvp of %s as uid=%d gid=%d\n", prog, uid, gid);
	fflush (stdout);
	execlp (prog, prog, argv, NULL);
	return 0;
}

