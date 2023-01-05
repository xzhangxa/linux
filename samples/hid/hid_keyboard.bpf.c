// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "hid_keyboard.h"
#include "hid_bpf_helpers.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, u8);
	__type(value, u64);
} key_stroke SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static int get_stream_asus(struct hid_bpf_ctx *hctx, u8 *modifier, u8 scancode[])
{
	int i;
	u8 *data;

	// read report id and modifier byte
	data = hid_bpf_get_data(hctx, 0, 11);
	if (!data)
		return -1;

	*modifier = data[1];
	for (i = 0; i < 6; i++)
		scancode[i] = data[i + 3];

	// return if it's not report id 1
	if (data[0] != 0x01)
		return -1;
	// return if it's key release event
	if (*modifier == 0x00 && scancode[0] == 0x00)
		return -1;

	return 0;
}

static int get_stream_k860(struct hid_bpf_ctx *hctx, u8 *modifier, u8 scancode[])
{
	int i;
	u8 *data;

	// read report id and modifier byte
	data = hid_bpf_get_data(hctx, 0, 8);
	if (!data)
		return -1;

	*modifier = data[1];
	for (i = 0; i < 6; i++)
		scancode[i] = data[i + 2];

	// return if it's not report id 1
	if (data[0] != 0x01)
		return -1;
	// return if it's key release event
	if (*modifier == 0x00 && scancode[0] == 0x00)
		return -1;

	return 0;
}

SEC("fmod_ret/hid_bpf_device_event")
int BPF_PROG(save_keystroke, struct hid_bpf_ctx *hctx)
{
	u8 scancode[6];
	u8 modifier;
	u64 *orig;
	u64 times, ts;
	struct event *e;
	int i;

	if (get_stream_asus(hctx, &modifier, scancode) != 0)
		return 0;

	// update BPF map
	for (i = 0; i < 6; i++) {
		orig = bpf_map_lookup_elem(&key_stroke, &scancode[i]);
		if (orig)
			times = *orig;
		else
			times = 0;
		times += 1;
		bpf_map_update_elem(&key_stroke, &scancode[i], &times, BPF_ANY);
	}

	// send ringbuf
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	for (i = 0; i < 6; i++)
		e->scancode[i] = scancode[i];
	e->modifier = modifier;

	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("fmod_ret/hid_bpf_rdesc_fixup")
int BPF_PROG(hid_rdesc_fixup, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0, 4096);

	if (!data)
		return 0;

	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
