# CantReadTh1s
Just a simple encryption / decryption tool

Not suited for real cryptographic security.
Please mess with it, but don't use it for anything important

## Usage:
```
    cantreadth1s [--info <file info> --out <fname> --testing] <filename>
```
#### If \<filename\> is an encrypted file:
- Will display the information about the file (passed by the --info option when it was created)
- Will ask password for decryption
- if --out option is set, will write to the file specified
- else, will display the result to stdout

#### If \<filename\> is a non-encrypted file:
- Will ask password for encryption
- Will store the information about the file (passed by the --info option, default info is the version of CantReadTh1s used)
- Will create file \<filename\>.cant_read_th1s which contains the compressed and encrypted data

### Data verification
A file processed by this tool will get a header containing the data SHA256 hash, and the length of the data.
This way a corrupted / manipulated data will get detected by the tool and the user will be notified.

### Technical details
- Data is stored encrypted using AES 256
- Data compressed with zlib
- Header stored in JSON, previously compressed with SMAZ
- Password Key Derivation with Argon2, with flexible settings (defaults are t=128, m=32, p=8)

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

loaded = crt.handle_file("test.cant_read_this")
print(loaded == plain_data)
```

### Exemples
```
cantreadthis secret_data
```
Will create a file named "secret_data.cant_read_this" processed

```
cantreadth1s --info "the password is TATA" secret_data
```
Will create the file secret_data.cant_read_this
When someone will try to decrypt this file with cantreadth1s again, it will display the information
"the password is TATA". (This is a terrible idea, don't do this)

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

### TODO plans

In order of priority
* Non-interactive password prompt (directly from function call)
* Split file into smaller chunks (and reverse process)
* Verifications of the tool security
* Use steganography to store the data inside an image (and reverse process)
* Split file into smaller chunks inside a list of images by steganography (and reverse process)
* Optimizing the tool data handling processes (for big files)
* Benchmarking
* Adding encryption & compression choices
