#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "shell.h"
#include "msg.h"

extern int ndn_ping(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "ndnping", "start ndn-ping client and server", ndn_ping },
    { NULL, NULL, NULL }
};

int main(void)
{
    /* start shell */
    puts("All up, running the shell now");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
