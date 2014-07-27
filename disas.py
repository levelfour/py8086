#!/usr/bin/env python
# coding: utf-8

import sys, os
import re
import argparse
import abc

HEADER_SIZE = 16
BYTE	= 1
WORD	= 2
DWORD	= 4

class Analyzer(metaclass=abc.ABCMeta):
	def __init__(self, binary):
		self.header = binary[0:HEADER_SIZE]
		self.tsize = self.fetch(2, target=self.header, offset=2)
		self.dsize = self.fetch(2, target=self.header, offset=4)
		self.bytecode = binary[HEADER_SIZE:HEADER_SIZE+self.tsize+self.dsize]
		self.pointer = 0

	def fetch(self, size=BYTE, target=[], offset=0):
		"""
		fetch data from target as form of little-endian
		* do not send pointer forward *
		"""
		if target== []:
			target = self.bytecode
			offset = self.pointer + offset
		try:
			if size == BYTE:
				return target[offset:offset+1][0]
			elif size == WORD:
				return (target[offset] | target[offset+1] << 8)
			elif size == DWORD:
				raise NotImplementedError("DWORD fetch")
		except IndexError as e:
			return None

	def read(self, size=BYTE):
		"""
		read data from self.bytecode as form of little-endian
		* send self.pointer forward *
		"""
		code = self.fetch(size)
		self.pointer += size
		return code

	def next(self, length):
		"""
		send self.pointer forward
		"""
		self.pointer += length

	def end(self):
		"""
		check if self.pointer reaches to the end of text section
		"""
		return self.tsize <= self.pointer

	def exec(self):
		""" run analyzer """
		return self.solve(
				self.fetch(offset=0),
				self.fetch(offset=1),
				self.fetch(offset=2),
				self.fetch(offset=3))

	@abc.abstractmethod
	def solve(self, c0, c1, c2, c3):
		"""
		override this method to make applicable work in derived class
		"""
		pass

class Disassembler(Analyzer):
	def str(self, length):
		"""
		convert byte code to applicable form of str
		return encode string and codes length
		"""
		p = self.pointer
		charlist = ["{:0>2x}".format(c)
				for c in self.bytecode[self.pointer:self.pointer+length]]
		padding = "  " * (6 - len(charlist))
		self.next(length)
		return "{:0>4x}: {}{}".format(
				p, "".join(charlist), padding)

	def solve(self, c0, c1, c2, c3):
		"""
		convert byte code to assemble code
		"""
		d = ""	# disassemble code
		s = ""	# result string
		if c0 == 0xb8:
			im = self.fetch(WORD, offset=1)
			d = "mov ax, {:0>4x}".format(im)
			s = self.str(3)
		elif c0 == 0xb9:
			im = self.fetch(WORD, offset=1)
			d = "mov cx, {:0>4x}".format(im)
			s = self.str(3)
		elif c0 == 0xbb:
			im = self.fetch(WORD, offset=1)
			d = "mov bx, {:0>4x}".format(im)
			s = self.str(3)
		elif (c0, c1) == (0x80, 0x2e):
			addr = self.fetch(WORD, offset=2)
			im = self.fetch(offset=4)
			d = "sub byte [{:0>4x}], {:0>2x}".format(addr, im)
			s = self.str(5)
		elif (c0, c1) == (0x81, 0x2e):
			addr = self.fetch(WORD, offset=2)
			im = self.fetch(WORD, offset=4)
			d = "sub [{:0>4x}], {:0>4x}".format(addr, im)
			s = self.str(6)
		elif (c0, c1) == (0x88, 0x07):
			d = "mov [bx], al"
			s = self.str(2)
		elif (c0, c1) == (0x88, 0x67):
			offset = self.fetch(offset=2)
			d = "mov [bx+{}], ah".format(offset)
			s = self.str(3)
		elif (c0, c1) == (0x89, 0x07):
			d = "mov [bx], ax"
			s = self.str(2)
		elif (c0, c1) == (0x89, 0x0f):
			d = "mov [bx], cx"
			s = self.str(2)
		elif (c0, c1) == (0x89, 0x2f):
			d = "mov [bx], bp"
			s = self.str(2)
		elif (c0, c1) == (0x89, 0x4f):
			offset = self.fetch(offset=2)
			d = "mov [bx+{}], cx".format(offset)
			s = self.str(3)
		elif c0 == 0xb1:
			im = self.fetch(offset=1)
			d = "mov cl, {:0>2x}".format(im)
			s = self.str(2)
		elif c0 == 0xb5:
			im = self.fetch(offset=1)
			d = "mov ch, {:0>2x}".format(im)
			s = self.str(2)
		elif (c0, c1) == (0xc6, 0x07):
			im = self.fetch(offset=2)
			d = "mov byte [bx], {:0>2x}".format(im)
			s = self.str(3)
		elif (c0, c1) == (0xc6, 0x47):
			offset = self.fetch(offset=2)
			im = self.fetch(offset=3)
			d = "mov byte [bx+{}], {:0>2x}".format(offset, im)
			s = self.str(4)
		elif (c0, c1) == (0xc6, 0x06):
			addr = self.fetch(WORD, offset=2)
			im = self.fetch(offset=4)
			d = "mov byte [{:0>4x}], {:0>2x}".format(addr, im)
			s = self.str(5)
		elif (c0, c1) == (0xc7, 0x06):
			addr = self.fetch(WORD, offset=2)
			im = self.fetch(WORD, offset=4)
			d = "mov [{:0>4x}], {:0>4x}".format(addr, im)
			s = self.str(6)
		elif (c0, c1) == (0xc7, 0x07):
			im = self.fetch(offset=2)
			d = "mov [bx], {:0>4x}".format(im)
			s = self.str(4)
		elif (c0, c1, c2) == (0xc7, 0x46, 0x00):
			im = self.fetch(WORD, offset=3)
			d = "mov [bp], {:0>4x}".format(im)
			s = self.str(5)
		elif (c0, c1) == (0xc7, 0x47):
			offset = self.fetch(offset=2)
			im = self.fetch(WORD, offset=3)
			d = "mov [bx+{}], {:0>4x}".format(offset, im)
			s = self.str(5)
		elif c0 == 0xcd:
			im = self.fetch(offset=1)
			d = "int {}".format(im)
			s = self.str(2)
		elif c0 == 0x01:
			d = "; sys exit"
			s = self.str(1)
		elif c0 == 0x04:
			s = self.str(1)
			d = "; sys write\n{}  ; arg\n{}  ; arg".format(
					self.str(2), self.str(2))
		else:
			d = "?"
			s = self.str(1)
		return "{}  {}".format(s, d)

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("-d", "--disas", action="store_true")
	parser.add_argument("filename")
	args = parser.parse_args()

	with open(args.filename, "rb") as f:
		if args.disas == True:
			disassembler = Disassembler(f.read())
			while not disassembler.end():
				print(disassembler.exec())
		else:
			raise NotImplementedError("sorry for inconvenience")
