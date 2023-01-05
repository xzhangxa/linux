// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Benjamin Tissoires
 *
 * This is a pure HID-BPF example, and should be considered as such:
 * on the Etekcity Scroll 6E, the X and Y axes will be swapped and
 * inverted. On any other device... Not sure what this will do.
 *
 * This C main file is generic though. To adapt the code and test, users
 * must amend only the .bpf.c file, which this program will load any
 * eBPF program it finds.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "hid_keyboard.h"
#include "hid_keyboard.skel.h"
#include "hid_bpf_attach.h"

const char *hid_key_to_str[104] = {
	"", "ERR_OVF", "POST_FAIL", "UND", "a",		// 0
	"b", "c", "d", "e", "f",				// 5
	"g", "h", "i", "j", "k",				// 10
	"l", "m", "n", "o", "p",				// 15
	"q", "r", "s", "t", "u",				// 20
	"v", "w", "x", "y", "z",				// 25
	"1", "2", "3", "4", "5",				// 30
	"6", "7", "8", "9", "0",				// 35
	"ENTER", "ESC", "BACKSPACE", "TAB", "SPACE",		// 40
	"-", "=", "[", "]", "\\",				// 45
	"HASHTILDE", ";", "\'", "`", ",",			// 50
	".", "/", "CAPS", "F1", "F2",				// 55
	"F3", "F4", "F5", "F6", "F7",				// 60
	"F8", "F9", "F10", "F11", "F12",			// 65
	"SYSRQ", "SCROLLLOCK", "PAUSE", "INS", "HOME",		// 70
	"PAGEUP", "DEL", "END", "PAGEDOWN", "RIGHT",		// 75
	"LEFT", "DOWN", "UP", "NUMLOCK", "KPSLASH",		// 80
	"KPASTERISK", "KPMINUS", "KPPLUS", "KPENTER", "KP1",	// 85
	"KP2", "KP3", "KP4", "KP5", "KP6",			// 90
	"KP7", "KP8", "KP9", "KP0", "KPDOT",			// 95
	"102ND", "COMPOSE", "POWER", "KPEQUAL",			// 100
};

static bool running = true;

static void int_exit(int sig)
{
	running = false;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"%s: %s /sys/bus/hid/devices/0BUS:0VID:0PID:00ID\n\n"
		"The stream bytes order follows Asus ROG Z16 laptop keyboard, "
		"and may not work with other USB keyboards\n",
		__func__, prog);
}


static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char mod_str[80];

	sprintf(mod_str, "'%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s'",
		(e->modifier & 0x1) ? "l_ctrl" : "",
		(e->modifier & 0x2) ? "l_shift" : "",
		(e->modifier & 0x4) ? "l_alt" : "",
		(e->modifier & 0x8) ? "l_meta" : "",
		(e->modifier & 0x10) ? "r_ctrl" : "",
		(e->modifier & 0x20) ? "r_shift" : "",
		(e->modifier & 0x40) ? "r_alt" : "",
		(e->modifier & 0x80) ? "r_meta" : "");

	printf("Pressing: scancode '%s' '%s' '%s' '%s' '%s' '%s', modifier %s\n",
		hid_key_to_str[e->scancode[0]],
		hid_key_to_str[e->scancode[1]],
		hid_key_to_str[e->scancode[2]],
		hid_key_to_str[e->scancode[3]],
		hid_key_to_str[e->scancode[4]],
		hid_key_to_str[e->scancode[5]],
		mod_str);

	return 0;
}

static int get_hid_id(const char *path)
{
	const char *str_id, *dir;
	char uevent[1024];
	int fd;

	memset(uevent, 0, sizeof(uevent));
	snprintf(uevent, sizeof(uevent) - 1, "%s/uevent", path);

	fd = open(uevent, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return -ENOENT;

	close(fd);

	dir = basename((char *)path);

	str_id = dir + sizeof("0003:0001:0A37.");
	return (int)strtol(str_id, NULL, 16);
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct hid_keyboard *skel;
	struct bpf_program *prog;
	int err;
	const char *optstr = "";
	const char *sysfs_path;
	int opt, hid_id, attach_fd;
	struct attach_prog_args args = {
		.retval = -1,
	};
	LIBBPF_OPTS(bpf_test_run_opts, tattr,
                    .ctx_in = &args,
		    .ctx_size_in = sizeof(args),
	);

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	sysfs_path = argv[optind];
	if (!sysfs_path) {
		perror("sysfs");
		return 1;
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	skel = hid_keyboard__open_and_load();
	if (!skel) {
		fprintf(stderr, "%s  %s:%d", __func__, __FILE__, __LINE__);
		return -1;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	hid_id = get_hid_id(sysfs_path);

	if (hid_id < 0) {
		fprintf(stderr, "can not open HID device: %m\n");
		return 1;
	}
	args.hid = hid_id;

	attach_fd = bpf_program__fd(skel->progs.attach_prog);
	if (attach_fd < 0) {
		fprintf(stderr, "can't locate attach prog: %m\n");
		return 1;
	}

	bpf_object__for_each_program(prog, *skel->skeleton->obj) {
		/* ignore syscalls */
		if (bpf_program__get_type(prog) != BPF_PROG_TYPE_TRACING)
			continue;

		args.retval = -1;
		args.prog_fd = bpf_program__fd(prog);
		err = bpf_prog_test_run_opts(attach_fd, &tattr);
		if (err) {
			fprintf(stderr, "can't attach prog to hid device %d: %m (err: %d)\n",
				hid_id, err);
			return 1;
		}
	}

	while (running) {
		err = ring_buffer__poll(rb, 250 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	hid_keyboard__destroy(skel);

	return 0;
}
