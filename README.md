# CantReadTh1s
Just a simple encryption / decryption tool

Not suited for real cryptographic security.
Please mess with it, but don't use it for anything important

## Usage:
```
    cantreadth1s [--out <fname> --testing] <filename>
```
#### If <filename> is an encrypted file:
- Will ask password for decryption
- if --out option is set, will write to the file specified
- else, will display the result to stdout

#### If <filename> is a non-encrypted file:
- Will ask password for encryption
- Will create file <filename>.cant_read_th1s which contains the compressed and encrypted data

### Data verification
A file processed by this tool will get a header containing the data SHA256 hash, and the length of the data.
This way a corrupted / manipulated data will get detected by the tool and the user will be notified.

### Technical details
Data is stored encrypted using AES 256, compressed with zlib.

### Python usage
The "CantReadThis" class permits any other script to very simply load the tool into an existing project:
```
import random, string
from cantreadth1s import CantReadThis

plain_data = ''.join([random.choice(string.printable) for i in range(500)])
with open("test", "w") as f:
    f.write(plain_data)

crt = CantReadThis()
crt.handle_file("test") # Will ask for password and output to a test.cant_read_this file

with open("test.cant_read_this", "rb") as f:
    ld = f.read()
loaded = crt.handle_data(ld)
print(loaded == plain_data)
```

### Exemples
```
cantreadthis secret_data
```
Will create a file named "secret_data.cant_read_this" processed

```
cantreadth1s --out outfile secret_data.cant_read_this
```
Will output to file "outfile" the data recovered from secret_data.cant_read_this

```
cantreadthis secret_message.cant_read_this
```
Will print on the screen the data recovered from secret_message.cant_read_this

```
cantreadth1s --testing foo
```
Will launch tests (filename doesn't matter)
