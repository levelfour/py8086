#!/usr/bin/env python
# coding: utf-8

import sys, os
import argparse

def disas(code):
	print(code)

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
