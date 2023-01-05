#ifndef _HID_KEYBOARD_H_
#define _HID_KEYBOARD_H_


struct event {
	__u8 scancode[6];
	__u8 modifier;
};

#endif // _HID_KEYBOARD_H_
