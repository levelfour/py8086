#!/usr/bin/env python
# coding: utf-8

import sys, os
import re
import argparse

HEADER_SIZE = 16
BYTE	= 1
WORD	= 2
DWORD	= 4

class Analyzer:
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
		if size == BYTE:
			return target[offset:offset+1][0]
		elif size == WORD:
			return (target[offset] | target[offset+1] << 8)
		elif size == DWORD:
			raise NotImplementedError("DWORD fetch")

	def read(self, size=BYTE):
		"""
		read data from self.bytecode as form of little-endian
		* send self.pointer forward *
		"""
		code = self.fetch(size)
		self.pointer += size
		return code

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
	
	def next(self, length):
		self.pointer += length

	def disas(self, sys=-1):
		c = self.fetch()	# byte code
		d = ""				# disassemble code
		s = ""				# result string
		if c == 0xb8:
			im = self.fetch(WORD, offset=1)
			d = "mov ax, {:0>4x}".format(im)
			s = self.str(3)
		elif c == 0xcd:
			im = self.fetch(offset=1)
			d = "int {}".format(im)
			s = self.str(2)
		elif c == 0x01:
			d = "; sys exit"
			s = self.str(1)
		elif c == 0x04:
			d = "; sys write\n{}  ; arg\n{}  ; arg".format(
					self.str(2), self.str(2))
			s = self.str(1)
		else:
			s = self.str(1)
			d = "?"
		return "{}  {}".format(s, d)

	def end(self):
		return self.tsize <= self.pointer

def disas(binary):
	analyzer = Analyzer(binary)
	while not analyzer.end():
		print(analyzer.disas())

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("-d", "--disas", action="store_true")
	parser.add_argument("filename")
	args = parser.parse_args()

	with open(args.filename, "rb") as f:
		if args.disas == True:
			disas(f.read())
		else:
			raise NotImplementedError("sorry for inconvenience")
