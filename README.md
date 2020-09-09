# hashf

Rename files to their hash digests.

Files downloaded from the internet often have useless names, and it is more
effort than it is worth to give each file a meaningful name. To reduce
duplicates, avoid quoting and spacing issues, and to keep things generally tidy
in the laziest way possible, `hashf` allows you to quickly rename batches of
files to the hash digests of their contents.

- supports MD5, SHA1, and SHA256 hashing algorithms
- allows you to change the destination directory of the rename
- allows you to copy as well as rename the files
