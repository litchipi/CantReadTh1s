# CantReadTh1s
Just a simple encrypted backup tool, provides encryption and compression of data.

Made to be as much secure as possible.
Please mess with it, but don't use it for anything important.

## Overview
Simple CLI tool to backup important files and encrypt them.
```
cantreadth1s myfile
```
Process a file, outputs in myfile.crt (pass --outfile <filename> to modify the output file name)
```
cantreadth1s myfile.crt
```
Loads a file, outputs in myfile (pass --outfile <filename> to modify the output file name)

Can be imported inside a Python code to be used to create processed files from inside a code, or to process a dict, returning an encrypted and compressed dict

Uses:
    sha256 for checksum
    argon2 for key derivation
    AES OFB for encryption
    zlib for compression    (also available: lzma, bz2, lz4 or no compression)

## Security level
The security level is by default 1. It acts on the process as:
- Argon2 options are increased in value (except parallel), resulting in more time needed to compute password derived key
- Multiple passes in AES encryption
- A longer seed used for password derivation

There is no theoric limit to the security level.
``` 
cantreadth1s -s 30 veryimportantfile
```
Process a file with a security level of 30

## Tweaks
Every parameter can be tweaked from the Python object (or cli if you add some argument parser options).
This way you can have custom argon2 parameters.

The default memory allowed for the processing is 10M, the data will then be read, compressed and encrypted 10M at a time.
Note: that doesn't mean only 10M of RAM will be used.

## Exemples
```
cantreadth1s file0 file1 file2
cantreadth1s --password neverdothis file0
cantreadth1s my_dir/
cantreadth1s my_dir.dir.crt
cantreadth1s my_dir_2/ file0
cantreadth1s --verbose
cantreadth1s --info "This is my secured file"
cantreadth1s --help
```

## Upcoming evolutions
You are welcome if you want to help
- Secured metadata inside the encrypted payload
- Randomized output filenames (with filename restoration on load)
- FileObject behavior on Python (supporting open, close, write and read)
- multiprocessing for compression / encryption
- file division in multiple parts
- Steganography (just for fun)

