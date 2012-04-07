/*
 * hostapd reconfig utility used for WPS
 * Copyright (c) 2009, Atheros Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>

char **arg;
pid_t child_pid;

void start_hostapd(void)
{
    child_pid = fork();
    if ( child_pid == 0 ) {
        //printf("Starting hostapd (%d)\n", getpid());
        execv("./hostapd", arg);
        _exit( 0 );
    } else {
        wait(NULL);
    }
}

void kill_hostapd(void)
{
    //printf("Kill hostapd (%d)\n", child_pid);
    if(child_pid > 1) {
        kill(child_pid, SIGTERM);
    }
}

void sig_exit(int sig_num)
{
    kill_hostapd();
    _exit(0);
}

void sig_from_hostapd(int sig_num)
{
    signal(SIGUSR1, sig_from_hostapd);
    sleep(1);
    kill_hostapd();
}

int main(int argc, char *argv[]) {
    arg = argv;
    signal(SIGTERM, sig_exit); 
    signal(SIGUSR1, sig_from_hostapd); 
    while(1) {
        start_hostapd();
        sleep(1);
    }
    return 0;
}
