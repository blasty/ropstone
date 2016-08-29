#!/usr/bin/env python

"""ropstone

Usage:
    ropstone.py [-b ADDR] [-a ARCH] [-m MODE(s)] <FILE> <PATTERN>
    ropstone.py -A
    ropstone.py -a <ARCH> -M

Finds code gadgets in a given ELF/binary file

Arguments:
  FILE     input ELF/binary file
  PATTERN  hex pattern ('?' is nibble wildcard) or assembly code

options:
  -h, --help        display help output
  -a, --arch ARCH   specify architecture
  -A, --list-arch   list all available architectures
  -m, --mode MODE   specify architecture mode parameters (comma separated)
  -M, --list-mode   list all architecture mode parameters
  -b, --base ADDR   specify base address
"""

import sys
import re

from capstone import *
from keystone import *
from elftools.elf.elffile import ELFFile
from docopt import docopt

class ropstone():
    BANNER_STR = ">> ropstone v0.1 by blasty <peter@haxx.in>"
    bin_chunks = []

    arch = None
    modes = []
    base_addr = 0

    archs = [
        {
            "name"     : "arm",
            "cs_const" : CS_ARCH_ARM,
            "ks_const" : KS_ARCH_ARM,
            "boundary" : 4,
            "modes"    : [
                {
                    "name"     : "thumb",
                    "desc"     : "THUMB processor mode",
                    "cs_const" : CS_MODE_THUMB,
                    "ks_const" : KS_MODE_THUMB,
                    # this overrides the boundary of the parent architecture
                    "boundary" : 2,
                    # this adds a shift offset to the output addr to force THUMB mode
                    "retshift" : 1
                },
                {
                    "name"     : "le",
                    "desc"     : "Little endian",
                    "cs_const" : CS_MODE_LITTLE_ENDIAN,
                    "ks_const" : KS_MODE_LITTLE_ENDIAN,
                },
                {
                    "name"     : "be",
                    "desc"     : "Big endian",
                    "cs_const" : CS_MODE_BIG_ENDIAN,
                    "ks_const" : KS_MODE_BIG_ENDIAN,
                }
            ]
        },
        {
            "name"     : "x86",
            "cs_const" : CS_ARCH_X86,
            "ks_const" : KS_ARCH_X86,
            "boundary" : 1,
            "modes"    : [
                {
                    "name"     : "32b",
                    "desc"     : "x86 32bit",
                    "cs_const" : CS_MODE_32,
                    "ks_const" : KS_MODE_32
                },
                {
                    "name"     : "64b",
                    "desc"     : "x86_64 64bit",
                    "cs_const" : CS_MODE_64,
                    "ks_const" : KS_MODE_64
                }
            ]
        }
    ]

    def error(self, errstr):
        sys.stderr.write("ERROR: " + errstr + "\n")
        exit(-1)

    def get_arch_by_name(self, name):
        for arch in self.archs:
            if arch['name'] == name:
                return arch

        return None

    def get_mode_by_name(self, arch, name):
        for mode in arch['modes']:
            if mode['name'] == name:
                return mode

        return None

    def list_archs(self):
        print " > Architecture list:"
        for arch in self.archs:
            print "  - " + arch['name']
        print ""

    def list_modes(self):
        print " > Mode parameters for architecture '%s':" % (self.arch['name'])
        for mode in self.arch['modes']:
            print " - %s : %s" % (mode['name'], mode['desc'])
        print ""

    def is_elf(self, filename):
        magic = open(filename, "rb").read(4)

        if magic == chr(0x7f)+"ELF":
            return True

        return False

    def assemble_str(self, asm_code):
        ks_mode = 0

        for mode in self.modes:
            ks_mode = ks_mode | mode['ks_const']

        ks = Ks(self.arch['ks_const'], ks_mode)
        encoding, count = ks.asm(asm_code)

        o=""
        for v in encoding:
            o += chr(v)

        return o

    def find_pattern(self, data, matchstring):
        matches = []

        # convert match string to valid regex
        matchstring = matchstring.replace("?", ".")

        regex = re.compile(matchstring)
        for match in regex.finditer(data.encode("hex")):
            # skip non-byte aligned matches
            if (match.start() % 2) != 0:
                continue

            addr = match.start() / 2

            # keep architecture alignment in mind
            if (addr % self.arch['boundary']) != 0:
                continue

            matches.append({ "addr" : addr, "pattern" : match.group() })

        return matches

    def __init__(self):
        print "\n" + self.BANNER_STR + "\n"

        arguments = docopt(__doc__)

        # docopt beats argparse, but I don't like crap in my dicts
        self.arguments = {k.strip('-<>'): v for k, v in arguments.items()}

        if self.arguments['base'] is not None:
            self.base_addr = int(self.arguments['base'], 0)

        # check if input file is ELF, if so: determine ARCH and MODE
        if self.arguments['FILE'] is not None:
            if self.is_elf(self.arguments['FILE']):
                f = open(self.arguments['FILE'], "rb")

                elffile = ELFFile(f)

                march = elffile.get_machine_arch()

                if march == "x64":
                    self.arch = self.get_arch_by_name("x86")
                    self.modes.append(self.get_mode_by_name(self.arch, "64b"))
                elif march == "x86":
                    self.arch = self.get_arch_by_name("x86")
                    self.modes.append(self.get_mode_by_name(self.arch, "32b"))
                elif march == "ARM":
                    self.arch = self.get_arch_by_name("arm")
                    if elffile.little_endian:
                        self.modes.append(self.get_mode_by_name(self.arch, "le"))
                    else:
                        self.modes.append(self.get_mode_by_name(self.arch, "be"))
                else:
                    self.error("ELF has unsupported machine type. (0x%x)" % elffile['e_machine'])

                for i in xrange(elffile.num_sections()):
                    section = elffile.get_section(i)

                    if section['sh_type'] != "SHT_PROGBITS":
                        continue

                    if not (section['sh_flags'] & 0x04):
                        continue

                    self.bin_chunks.append({
                        'name' : section.name,
                        'addr' : section['sh_addr'],
                        'data' : section.data()
                    })
            else:
                self.bin_chunks.append({
                    'name' : "RAW",
                    'addr' : self.base_addr,
                    'data' : open(self.arguments['FILE'], "rb").read()
                })

        if self.arguments['arch']:
            self.arch = self.get_arch_by_name(self.arguments['arch'])

            if self.arch is None:
                self.error("Invalid architecture specified! (use -A for architecture list)")

        if self.arguments['mode']:
            if self.arch is None:
                self.error("No architecture specified! (use -A for architecture list)")

            s_modes = self.arguments['mode'].split(",")

            for i in xrange(len(s_modes)):
                for mode in self.arch['modes']:
                    if mode['name'] == s_modes[i]:
                        self.modes.append(mode)

        if self.arguments['list-arch']:
            self.list_archs()
        elif self.arguments['list-mode']:
            if self.arch is None:
                self.error("Invalid (or no) architecture specified! (use -A for architecture list)")

            self.list_modes()
        else:
            # figure out if parameter is a hex pattern or asm code
	    if re.search("^[0-9a-f\?]+$", self.arguments['PATTERN']) != None:
                pattern = self.arguments['PATTERN']
            else:
                pattern = self.assemble_str(self.arguments['PATTERN']).encode('hex')

            num_hits = 0

            print "> searching for pattern '%s'\n" % (pattern)

            cs_mode = 0
            retshift = 0

            for mode in self.modes:
                cs_mode = cs_mode | mode['cs_const']

                # check for mode specific overrides (only needed for THUMB atm)
                if "boundary" in mode:
                    self.arch['boundary'] = mode['boundary']
                if "retshift" in mode:
                    retshift = mode['retshift']

            md = Cs(self.arch['cs_const'], cs_mode)

            for chunk in self.bin_chunks:
                matches = self.find_pattern(chunk['data'], pattern)

                if len(matches) > 0:
                    print "> hits in '%s':" % (chunk['name'])

                num_hits = num_hits + len(matches)

                for match in matches:
                    bytecode = match['pattern'].decode('hex')
                    disas = []
                    for ins in md.disasm(bytecode, match['addr']):
                        disas.append("%s %s" % (ins.mnemonic, ins.op_str))

                    if len(disas) == 0:
                        disas = [ "<INVALID>" ]

                    print " + %08x | %s | %s" % (
                        chunk['addr']+match['addr']+retshift,
                        match['pattern'],
                        " ; ".join(disas)
                    )

                if num_hits == 0:
                    self.error("not a single match found, better luck next time! :(")
                else:
                    print ""
                    print "> %d hits found!" % (num_hits)
                    print ""

rs = ropstone()
