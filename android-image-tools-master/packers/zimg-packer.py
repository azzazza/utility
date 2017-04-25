#! /usr/bin/env python
#
# Author : acdev
# Email  : remittor@gmail.com

import sys
import struct
import os
import string
import optparse
import zlib
import gzip
import StringIO

options = None

def setup():
  global options
  parser = optparse.OptionParser("usage: %prog [options] \n" +
                                 "Try %prog -h' for more information.")

  parser.add_option("-d", "--dir", dest="dir",
                    default="." + os.path.sep + "boot_" + os.path.sep, type="string",
                    help="Unpacked boot directory (after AndImgTool.exe)")

  parser.add_option("-k", "--kernel", dest="kernel",
                    default="", type="string",
                    help="Patched kernel image")

  parser.add_option("-z", "--zimage", dest="zimage",
                    default="zImage", type="string",
                    help="Original compressed kernel image")

  parser.add_option("-o", "--outfile", dest="outfile",
                    default="zImage_new", type="string",
                    help="Output zImage filename")

  (options, args) = parser.parse_args()

def die(message):
  print message
  exit(1)

def find_file(path, name):
  for root, dirs, files in os.walk(path):
    if name in files:
      return os.path.join(root, name)
  return None

# ------------------------------------------------------
  
setup()  
dir = options.dir
if (not os.path.isdir(dir)):
  die("ERROR: Can't find dir %s" % dir)

# GZIP info: http://www.forensicswiki.org/wiki/Gzip

zimg_fn = find_file(dir, options.zimage)
if (zimg_fn == None):
  die("ERROR: Can't find file: " + options.zimage)
print "zImage     : " + zimg_fn

kernel1 = 'kernel_new.img'
kernel2 = 'kernel.img'
if (len(options.kernel) > 0):
  kernel1 = options.kernel
  kernel2 = options.kernel
  
knew_fn = find_file(dir, kernel1)
if (knew_fn == None):
  knew_fn = find_file(dir, kernel2)
if (knew_fn == None):
  die("ERROR: Can't find file: " + kernel2)
print "kernel_new : " + knew_fn

new_zimg_fn = os.path.dirname(zimg_fn) + os.path.sep + options.outfile
print "zImage_new : " + new_zimg_fn
  
  
zimg_file = open(zimg_fn, 'rb')
zimg_file.seek(0x24)
data = struct.unpack("III", zimg_file.read(4*3))
if (data[0] != 0x016f2818):
  die("ERROR: Can't found IMG magic number")
zimg_size = data[2]

zfile_size = os.path.getsize(zimg_fn)
if (zfile_size < zimg_size):
  die("ERROR: zImage size: %d (expected: %d)" % (zfile_size, zimg_size))

zimg_footer = ''
if (zfile_size > zimg_size):
  zimg_file.seek(zimg_size)
  zimg_footer = zimg_file.read()
  
zimg_file.seek(0)
zimg = zimg_file.read(zimg_size)
gz_begin = zimg.find('\x1F\x8B\x08\x00')
if (gz_begin < 0x24):
  die("ERROR: Can't found GZIP magic header")

zimg_file.close()
zimg_file = StringIO.StringIO()
zimg_file.write(zimg)

zimg_file.seek(gz_begin + 8)
data = struct.unpack("BB", zimg_file.read(2))
ext_flags = data[0]
print "extra flags: 0x%x" % ext_flags
os_type = data[1]
print "OS type    : 0x%x" % os_type
if (ext_flags != 2 and ext_flags != 4):
  die("ERROR: Can't support extra flags = 0x%x" % ext_flags)
  
zimg_file.seek(gz_begin)
gz_data = zimg_file.read() 

kernel_data = zlib.decompress(gz_data, 16 + zlib.MAX_WBITS)
if (kernel_data == None):
  die("ERROR: Can't decompress GZIP data")

#kernel_fn = dir + '/kernel/krnl'
#kernel_file = open(kernel_fn, 'wb')
#kernel_file.write(kernel_data)
#kernel_file.close()

kernel_size = len(kernel_data)
print "kernel_size: 0x%08x" % kernel_size
kernel_sz = struct.pack("I", kernel_size)
gz_end = zimg.rfind(kernel_sz)
print "gz_begin   : 0x%08x" % gz_begin
print "gz_end     : 0x%08x" % gz_end
if (gz_end < len(zimg) - 0x1000):
  die("ERROR: Can't find ends of GZIP data (gz_end = 0x%x)" % gz_end)

gz_end = gz_end + 4
gz_size = gz_end - gz_begin
print "gz_size    : 0x%08x" % gz_size

knew_file = open(knew_fn, 'rb')
knew_data = knew_file.read()
knew_file.close()

new_gz_data = StringIO.StringIO()
with gzip.GzipFile(fileobj = new_gz_data, mode = 'wb') as f:
  f.write(knew_data)
new_gz_data.seek(9)
new_gz_data.write(struct.pack("B", os_type))  
  
#knew_gz_fn = dir + '/kernel/kernel.gz'  
#knew_gz_file = open(knew_gz_fn, 'wb')
#knew_gz_file.write(new_gz_data.getvalue())
#knew_gz_file.close()

new_gz_data.seek(0, os.SEEK_END)
new_gz_size = new_gz_data.tell()
print "new_gz_size: 0x%08x" % new_gz_size

if (new_gz_size > gz_size):
  die("ERROR: Can't new GZIP size too large")

new_zimg_file = open(new_zimg_fn, 'wb')
zimg_file.seek(0)
new_zimg_file.write(zimg_file.read(gz_begin))
new_zimg_file.write(new_gz_data.getvalue())
new_zimg_file.write('\0'*(gz_size - new_gz_size))
zimg_file.seek(gz_end)
new_zimg_file.write(zimg_file.read())
new_zimg_file.write(zimg_footer)
new_zimg_file.close()

zimg_file.close()
new_gz_data.close()

new_zimg_file = open(new_zimg_fn, 'r+b')
new_zimg_file.seek(0)
pos = zimg.find(struct.pack("I", gz_end - 4))
if (pos < 0x24 or pos > 0x400 or pos > gz_begin):
  die("ERROR: Can't find offset of orig GZIP size field")
new_zimg_file.seek(pos)
new_zimg_file.write(struct.pack("I", gz_begin + new_gz_size - 4))
new_zimg_file.close()

print "Finish"
