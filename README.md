# CantReadTh1s
Just a simple encrypted backup tool, provides encryption and compression of data.

For now, not yet secured for real cryptographic security.
Please mess with it, but don't use it for anything important

## Usage:
```
usage: cantreadth1s [-h] [--outfile OUTFILE] [--display-only] [--info INFO] [--security-level SECURITY_LEVEL] [--find-parameters FIND_PARAMETERS] [--compression-algorithm {lzma,bz2,zlib,lz4,none}] [--verbose] [--password PASSWORD] filename

positional arguments:
  filename              The file you want to process/recover

optional arguments:
  -h, --help            show this help message and exit
  --outfile OUTFILE, -o OUTFILE
                        Where to save the recovered data
  --display-only, -d    Print result to stdout and do not write to file
  --info INFO, -i INFO  Information about the file, its content or an indication of the password
  --security-level SECURITY_LEVEL, -l SECURITY_LEVEL
                        Security level to use, changes the parameters of the password derivation function. Can go to infinite, default is 1.
  --find-parameters FIND_PARAMETERS, -f FIND_PARAMETERS
                        Tests the parameters needed to get the given execution time (in ms / Kib)
  --compression-algorithm {lzma,bz2,zlib,lz4,none}, -c {lzma,bz2,zlib,lz4,none}
                        The compression algorithm to use to process the data
  --verbose, -v         Display informations about the file and the process
  --password PASSWORD, -p PASSWORD
                        Password to use
```
#### If \<filename\> is an encrypted file:
- Will display the information about the file (passed by the --info option when it was created)
- Will ask password for decryption
- If --display is set, will display the result to stdout, else will output to file

#### If \<filename\> is a non-encrypted file:
- Will ask password for encryption
- Will store the information about the file (passed by the --info option, default info is the version of CantReadTh1s used)
- Will create file \<filename\>.cant_read_this which contains the compressed and encrypted data

### Data verification
A file processed by this tool will get a header containing a portion of the SHA256 hash, and the length of the data.
This way a corrupted / manipulated data will get detected by the tool and the user will be notified.

### Technical details
- Data is stored encrypted using AES 256
- Data compressed by default with Zlib
- Header stored in JSON
- Password Key Derivation with Argon2, with flexible settings (defaults are t=2, m=1024, p=Number of CPU x2)
On an AMD Ryzen 5 3600X (6 cores), processes rockyou.txt in 40 secs, compressed from 134M to 50.8M.

### Security levels
To fit particular needs, the tool can be used with different levels of security that can be added to the default minimal settings for more security.
This affects the password derivation function (Argon2 hash) parameters, but may affect other aspects too as the tool gets developped.
```
    cantreadth1s -l 50 <file>
```
Will process the file \<file\> with a level of security of 50.
```
    cantreadth1s -f 500 <dummyfile>
```
Will find the maximal security parameters in order to reach get ~500 ms/Kib of data processing time.

### Python usage
The "CantReadThis" class permits any other script to very simply load the tool into an existing project. A very simple example can be seen within the test_script.py file inside this repository.

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
cantreadthis --display secret_message.cant_read_this
```
Will print on the screen the data recovered from secret_message.cant_read_this

```
cantreadthis --compression-algorithm bz2 secret_message
```
Will use the bz2 compression algorithm to process the data

```
cantreadthis ./secret_directory/
```
Will process the directory ./secret_directory/, putting any file inside it (will ignore symlinks) to a zipfile, and then treat the zipfile. 
Will create a file called secret_directory_zipfile.cant_read_this
```
cantreadthis ./secret_directory_zipfile.cant_read_this
```
Will load the processed directory zipfile, then will extract the zipfile to the current directory

### TODO plans
In order of priority
* Class behaving like a FileObject to interact with crt file directly
* Improve Python class usability for usage inside other projects
* Split processed file into smaller chunks (and reverse process)
* Improve speed with Cython
* Verifications of the tool security
* Very simple GUI tool for non-cli users
* Comment the code :-(
* Use steganography to store the data inside an image (and reverse process)
* Split file into smaller chunks inside a list of images by steganography (and reverse process)
* Adding encryption choices
* Multiprocessing on compression
* Better benchmarking functions
