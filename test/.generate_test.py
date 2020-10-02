#!/usr/bin/env python3
#-*-encoding:utf-8*-

import sys
import string, random

n = sys.argv[1]
f = sys.argv[2]

with open(f, "w") as d:
    d.write("".join(random.choices(string.printable, k=int(n))))

