Overview
--------
Extended attributes for Windows — like xattr on Linux and macOS.

On Windows there's no default commandline tool to write or delete EAs.
To read EAs you may use: `fsutil file queryEA <path>`

Name requirements
-----------------
Unlike in Linux, where EA names require a specific name prefix like "user." or "system." in Windows names have the following restrictions:
It MUST be less than 255 8-bit ASCII characters and MUST NOT contain any of the following characters:
`ASCII values 0x00 - 0x1F, \ / : * ? " < > | , + = [ ] ;`
Beside that, in Windows user mode you'll NOT be able to create an EA name starting with `$KERNEL.`.
Names of EAs in Windows will be converted to all-uppercase upon creation automatically.

Value requirements
------------------
The EA value may just be a string, but may be any byte sequence up to a total length of 65535 bytes.

WSL2 Linux:
-----------
EAs are NOT propagated to the other side, neither from WSL2-Linux to Windows, nor the other way around.

Usage
-----
Similar to the commands of the Linux xattr, the following arguments may be supplied:

List only the names of all EAs on the given file(s):
```
xattr [-eklrvx] file [ file ... ]
```
Print only the value of EA ea_name on the given file(s):
```
xattr -p [-eklrvx] ea_name file [ file ... ]
```
Write the value of the EA ea_name to ea_value:
```
xattr -w [-fkrux] ea_name ea_value file [ file ... ]
    (No output on success, error messages on stderr.)
```
Delete the EA ea_name from file(s):
```
xattr -d [-kr] ea_name file [ file ... ]
    (No output on success, error messages on stderr.)
```
Clear all EA from the given file(s):
```
xattr -c [-kr] file [ file ... ]
    (No output on success, error messages on stderr.)
```
Options:

    -c  Clear all Attributes.

    -d  Delete the given attribute.

    -e  Expand / extract / examine well known EAs.

    -f  Write content of a given file as EA value. Max size is 65565 bytes.
        Use with -w option. This option can not be combined with -x or -u.

    -h  Help.

    -k  Keep-going. Ignore errors and continue processing the next file. 
        This is useful when you want to process a list of files and ignore errors on some of them.

    -l  By default, the first two command forms either display just the attribute names or
        values, respectively. The -l option causes both the attribute names and corresponding
        values to be displayed. For hex display of values, the output is preceeded with the hex
        offset values and followed by ASCII display, enclosed by '|'.

    -m  Max-depth for recursive processing. Default is 1. 
        0 => only the given directory, 
        1 => only the files in the given directory, 
        2 => files in the given directory and their subdirectories, etc.
        This option is only valid with -r option.

    -p  Print the value associated with the given attribute.

    -r  If a file argument is a directory, act as if the entire contents of the directory
        recursively were also specified (so that every file in the directory tree is acted upon).

    -u  Write value as unicode string (UTF-16LE). The Default is UTF-8. 
        This option can not be combined with -x.

    -v  View the file name, even for a single file.

    -w  Write a given attribute name with a value.

    -x  Force the attribute value to be displayed in the hexadecimal representation.
        This option can not be combined with -u.

    --debug  Print debug information to stdout.

One or more files or directories may be specified on the command line.

For the first two forms of the command, if there is more than one file, 
the file name is displayed along with the actual results. 
When only one file is specified, the display of the file name is suppressed unless the -v option, is also specified.

Attribute values are usually displayed as strings. However, if unprintable data are detected, the value is displayed in a hexadecimal representation.

The -w option normally assumes the input attribute value is a string. 
Specifying the -x option causes xattr to expect the input in hexadecimal (whitespace is ignored). 
The hex bytes must be enclosed in "".

xattr exits with 0 on success.
On error it exits with a non-zero value and prints an error message on stderr.

Misc
----
Although documented differently EAs are also supported on ReFS (Checked on Win11 24H2):
https://learn.microsoft.com/en-us/windows-server/storage/refs/refs-overview
Run "fsutil fsinfo volumeinfo D:" to see whether EAs are supported on your volume.

Some EA names Windows uses by default:
$CI.CATALOGHINT
$KERNEL.CFDONOTCONVERT
$KERNEL.PURGE.ESBCACHE
$KERNEL.PURGE.APPXFICACHE
$KERNEL.PURGE.TRUSTCLAIM

Some background on various EA usages:
https://posts.specterops.io/host-based-threat-modeling-indicator-design-a9dbbb53d5ea
https://superuser.com/questions/396692/what-are-these-extended-attributes-eas-in-the-files-in-windows-8
https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/Smart_App_Control/Studie_Smart_App_Control.pdf?__blob=publicationFile&v=2
https://posts.specterops.io/documenting-and-attacking-a-windows-defender-application-control-feature-the-hard-way-a-case-73dd1e11be3a
https://github.com/gabriellandau/ExtendedAttributeIpecac
https://superuser.com/questions/396692/what-are-these-extended-attributes-eas-in-the-files-in-windows-8


