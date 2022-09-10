# Linux notes: useful commands and tricks

## Disk operations (low level)

### Do a MBR backup

With partition table:

    dd if=/dev/hda of=/dev/fd0/mbr.bin bs=512 count=1 status=progress && sync

Without partition table:

    dd if=/dev/hda of=/dev/fd0/mbr.bin bs=446 count=1 status=progress && sync

### Restore a MBR backup

With partition table:

    dd if=/dev/fd0/mbr.bin of=/dev/hda bs=512 count=1 status=progress && sync

Without partition table:

    dd if=/dev/fd0/mbr.bin of=/dev/hda bs=446 count=1 status=progress && sync

### Clone disks

PS.: the parameter `bs=16M` can be faster to clone HDDs.
To clone HDDs with failures, use the parameter `conv=noerror`.

    dd if=/dev/sdb of=image.bin bs=32M status=progress && sync

## Partition and filesystem

### View UEFI information

    efibootmgr -v

### Make a MD5 sum of a directory's contents as one sum

    find [DIRECTORY] -type f -exec md5sum {} \; | sort -k 2 | md5sum

### Copy files with 'rsync'

Default behavior: Any files that do not exist on the 'source' are copied. Rsync is extremely efficient in that only the changed parts of files are copied, and if the file is the same if it is not copied over at all.

    rsync -a --progress [SRC_DIRECTORY] [DST_DIRECTORY]

Ignore existing files:

    rsync -a --progress --ignore-existing [SRC_DIRECTORY] [DST_DIRECTORY]

Overwrite only newer files (update):

    rsync -a --progress --update [SRC_DIRECTORY] [DST_DIRECTORY]

Delete files that have been deleted from the source directory:

    rsync -a --progress --delete [SRC_DIRECTORY] [DST_DIRECTORY]

Copy files and make hard links for identical files on a 'REF_DIRECTORY' (useful for making backups):

    rsync -a --progress --link-dest [REF_DIRECTORY] [SRC_DIRECTORY] [DST_DIRECTORY]

### Check partition filesystem

PS.: the partition must be unmounted in all cases.

Check a FAT32 partition:

    sudo dosfsck -a -r -w -v /dev/sdb1

Check a NTFS partition:

    sudo ntfsfix /dev/sdb1

Check a EXT4 partition:

    sudo fsck.ext4 -f /dev/sda1

### Scan for badblocks

Scans for bad blocks by writing some patterns (0xaa, 0x55, 0xff, 0x00) on every
block of the device read/write/corruption errors.
And corruption means comparison with previously written data.

    sudo badblocks -s -w /dev/sdb

### View files/disks in hexadeximal

    sudo xxd /dev/sdb | less

### List the UUID of all partitions

    sudo blkid

### Change the UUID of a partition

    sudo tune2fs /dev/[DEVICE] -U [NEW_UUID]

Or if you want generate it randomly:

    sudo tune2fs /dev/[DEVICE] -U random

### Change the UUID of a SWAP partition

    sudo swaplabel -U [NEW_UUID] /dev/sda3

### Build a floppy disk image

    dd if=/dev/zero of=floppy.img bs=1440k count=1 status=progress && sync
    mkfs.msdos -F 12 -n "LABEL" floppy.img

To mount:

    sudo mkdir /mnt/floppy/
    sudo mount -o loop floppy.img /mnt/floppy/

### Image file with multiple partitions

To mount:

    sudo losetup --find --partscan Lakka-Generic.x86_64-2.3.2.img

To umount:

    sudo losetup --detach /dev/loopX

### List mounted partitions

    lsblk

Or also:

    findmnt

### Mount a directory in the RAM

Edit the file `/etc/fstab` and add:

    tmpfs /tmp tmpfs rw,nosuid,noatime,nodev,size=4G,mode=1777 0 0

The common parameters on `mount` command or `fstab` file are:

| Param             | Description                                                                                 |
| ----------------- | ------------------------------------------------------------------------------------------- |
| `defaults`        | Use default settings. Equivalent to `rw`, `suid`, `dev`, `exec`, `auto`, `nouser`, `async`. |
| `rw` / `ro`       | Mount (read-write) / (read-only).                                                           |
| `suid` / `nosuid` | (Permit) / (Do not permit) the operation of suid, and sgid bits.                            |
| `dev` / `nodev`   | (Interpret) / (Do not interpret) character or block special devices on the file system.     |
| `exec` / `noexec` | (Permit) / (Do not permit) the execution of binaries from the filesystem.                   |
| `user` / `nouser` | (Permit) / (Do not permit) any user to mount the filesystem.                                |
| `sync` / `async`  | All I/O to the file system should be done (a)synchronously.                                 |
| `auto` / `noauto` | The filesystem (can be) / (will not) be automatically mounted at startup.                   |
| `noatime`         | Do not update inode access times on this filesystem.                                        |
| `umask=`          | Mask out the given permissions from all inodes read from the filesystem.                    |
| `mode=`           | Permissions of all directory inodes read from the filesystem.                               |
| `errors=`         | Behavior when an error is encountered. Can be: `continue`, `remount-ro`, `panic`.           |

### Mount a ISO CD image

    sudo mount -t iso9660 -o loop "image.iso" /mnt

### Build a ISO CD image from a directory

PS.: this command build a ISO with the filesystem: ISO9660 + Rock Ridge + Joliet.

    genisoimage -o "image.iso" -V "My Label" -A "Application ID" -sysid "System ID" -R -J [DIRECTORY]

### Build a ISO image from a disc

    isoinfo -d -i /dev/cdrom | grep -i -E 'block size|volume size'
    dd if=/dev/cdrom of=output.iso status=progress bs=[BLOCK_SIZE_FROM_ABOVE] count=[VOLUME_SIZE_FROM_ABOVE]

### Make a hybrid ISO from a bootable ISO (to boot with an USB flashdrive)

    isohybrid "image.iso"

### Make a USB flashdrive bootable (Windows or Linux)

    sudo apt install extlinux wimtools curl
    curl -L https://git.io/bootiso -O
    chmod +x bootiso
    sudo ./bootiso image.iso

### Boot a ISO image inside a filesystem

Edit the file `/etc/grub.d/40_custom` and add:

    menuentry "ISO Ubuntu 19.10 Custom" {
        # Insert modules needed in order to access the iso-file
        insmod part_gpt
        #insmod part_msdos

        #insmod ntfs
        insmod ext2

        # Insert module needed in order to find partition
        insmod search_fs_uuid

        # Set UUID of partition with the iso-image
        # and let grub2 find the partition
        # (save it's identifier to the variable $root)
        set uuid="0af7c1cc-23b0-4c62-bf66-ee3264d83f43"
        search --no-floppy --set=root --fs-uuid $uuid

        # Mount the iso image by addressing it with (partition)/path
        set iso="/Isos/Linux/ubuntu-20.04.1-desktop-amd64.iso"
        loopback loop ($root)$iso

        linux (loop)/casper/vmlinuz boot=casper iso-scan/filename=${iso} quiet splash
        initrd (loop)/casper/initrd
    }

And update the GRUB configuration with:

    sudo update-grub

### Change the partition numbers (e.g.: 'sda3' to 'sda2')

    sudo sfdisk -d /dev/sdb > table.conf
    sudo sfdisk /dev/sdb < table.conf

### Read SMART data from HDDs

    sudo smartctl --attributes /dev/sda

## Boot and GRUB tricks

### Repair the GRUB with a livecd

Mount the devices and do a chroot:

    # The sda2 is the root partition
    sudo mount /dev/sda2 /mnt

    # The sda1 is the EFI partition
    sudo mount /dev/sda1 /mnt/boot/efi

    for i in /dev /dev/pts /proc /sys; do sudo mount -B $i /mnt$i; done

    # Makes the network available (if you want)
    sudo cp /etc/resolv.conf /mnt/etc/

    # Make sure this is loaded
    modprobe efivars

    # Do a chroot
    sudo chroot /mnt

Reinstall and update GRUB:

    grub-install --recheck /dev/sda

Exit chroot pressing CTRL+D.

Unmount everything:

    for i in /sys /proc /dev/pts /dev; do sudo umount /mnt$i; done
    sudo umount /mnt/boot/efi
    sudo umount /mnt

### Add a key shortcut for a entry menu in GRUB

Edit the file `/boot/grub/grub.cfg` and add `--hotkey=w` for a specific entry.

After that, update the GRUB configuration with:

    sudo update-grub

### Disable OS prober (detect Windows from GRUB)

Edit the file `/etc/default/grub` and add the line:

    GRUB_DISABLE_OS_PROBER=true

After that, update the GRUB configuration with:

    sudo update-grub

## Devices

### Test input device events (hid, mouse, keyboard)

    sudo evtest

### Remapping keyboard (ou mouse) button events

Edit the file `/lib/udev/hwdb.d/60-keyboard.hwdb` then run:

    sudo udevadm hwdb --update

Alternatively, you can create a file in `/etc/udev/hwdb.d/`, for example: `/etc/udev/hwdb.d/99-keyboard-remap.hwdb`.

### Reload/restart udev rules

    sudo udevadm control --reload-rules
    sudo udevadm trigger

### See udev actions at runtime

    udevadm monitor

or

    udevadm monitor --property

### See udev logs

All messages are in

    tail -f /var/log/syslog

### See attribute from a device

    udevadm info --attribute-walk /sys/bus/usb/devices/3-1.2:1.0/video4linux/video0

## Kernel and hardware

### Workarounds using kernel parameters

Edit the file `/etc/default/grub` and add the following parameters on the variable `GRUB_CMDLINE_LINUX_DEFAULT`.

| Param           | Description                                       |
| --------------- | ------------------------------------------------- |
| `amd_iommu=off` | solve problem with iommu in AMD Ryzen processors. |
| `max_loop=256`  | Increase the number of 'loop' devices.            |

And update the GRUB configuration with:

    sudo update-grub

For more information, see:

- [Kernel parameters](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html)

### View module options loaded into the kernel

PS.: each file below is an option of the module, and its content is its value.

    /sys/module/[MODULE_NAME]/parameters/*

To initialize a module with a particular option (example):

    sudo echo "options ath9k nohwcrypt=1" > /etc/modprobe.d/ath9k.conf

### List loaded modules (and sort by size)

    lsmod | sort -k 2,2n

### Display information about a module

    modinfo [MODULE_NAME]

### Remove a module (don't use the example)

    rmmod --all --stacks [MODULE_NAME]

### Load a module

    modprobe [MODULE_NAME]

### Load modules at startup

For loading modules during boot, edit the file `/etc/initramfs-tools/modules`.

For loading modules after boot, edit the file `/etc/modules`.

Then run:

    sudo update-initramfs -u

### Add a specific module to the blacklist

Edit the file `/etc/modprobe.d/blacklist.conf` and put the module to blacklist.
The folder contains other blacklist files as well.

Then run:

    sudo update-initramfs -u

### Get information about serial ports

    dmesg | egrep --color 'serial | ttyS'

### Connect to a system through the serial port

    screen /dev/ttyS0 19200

Or also:

    gtkterm

Or also:

    cu -l /dev/ttyS0 -s 19200

Or also:

    minicom

### Allow the user to access the USB serial port

    sudo usermod -a -G dialout $USER

### Display monitor resolution and refresh rate

    xrandr

### List number of processors

    nproc --all

### Get information about processors

    grep "^model name.*:" /proc/cpuinfo

### Get information about RAM

    grep "^Mem.*:" /proc/meminfo

### Adjust swappiness

Uses 90% of RAM before Linux kernel begins swapping:

    sudo echo "vm.swappiness=10" >> /etc/sysctl.conf

## Debian package

### Install '.deb' package

    dpkg -i [PACKAGE_FILE]

### Uninstall '.deb' package

    dpkg -r [PACKAGE_FILE]

### Remove residual configs

    dpkg -l | grep '^rc' | awk '{print $2}' | xargs sudo apt-get -y purge

### List history of installed packages

    zgrep " install " /var/log/dpkg.*

### List installed packages

    dpkg -l | tail -n +6 | cut -f 3 -d ' '

Or also:

    dpkg --get-selections | grep -v "deinstall" | sed 's/\t.*//g'

Or also:

    apt --installed list | grep -v "Listing..." | sed 's/\/.*//g'

### List installed packages and sort by estimated size (which installed software packages use the most disk space)

    dpkg-query -Wf '${Installed-Size}\t${Package}\n' | sort -n

### Create a Debian binary package

    debuild -us -uc

### Create a Debian source package

    debuild -S

### Debian packing: clean temporary files

    debuild clean

### Debian packing: submit packages to the Launchpad

    dput ppa ../*.changes

P.S.: You need create the file `~/.dput.cf` with content:

    [ppa]
    fqdn = ppa.launchpad.net
    method = ftp
    incoming = ~cfgnunes/staging
    login = anonymous

### Forces to remove a package without removing its dependencies

    sudo dpkg -r --force-depends [PACKAGE_NAME]

### Add missing public keys

    sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-key A040830F7FAC5991

### Hold (pin) a version of a package

    sudo apt-mark hold [PACKAGE_NAME]

### Main apt directories

    /etc/apt/trusted.gpg.d
    /etc/apt/sources.list.d
    /var/cache/apt/archives
    /var/cache/apt/pkgcache.bin
    /var/cache/apt/srcpkgcache.bin

To clean all apt lists, run:

    sudo rm -rf /var/lib/apt/lists/archive*
    sudo rm -rf /var/lib/apt/lists/security*

### Check which package a particular command is from

    dpkg -S "$(whereis expand | cut -f 2 -d ' ')"

## Snap package

### Install tools

    sudo snap install snapcraft --classic
    sudo snap install multipass

### Compile a project

    snapcraft

### Clean a compiled project

    snapcraft clean

### Iterating over Parts lifecycle

For parts lifecycle, see: <https://snapcraft.io/docs/parts-lifecycle>

    snapcraft pull --shell
    snapcraft build --shell
    snapcraft stage --shell
    snapcraft prime --shell

### Testing your snap locally

    sudo snap install --devmode my_snap_amd64.snap

### Releasing your app (submit packages to the snapcraft.io)

    snapcraft login
    snapcraft upload my_snap_amd64.snap

## Network

### Iptables firewall: list all rules

    sudo iptables -L

### Iptables firewall: example that enables the ports 80, 8180, 5432 only for IP 200.131.4.0

    # Remove all rules before
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -t nat -F
    iptables -t mangle -F
    iptables -F
    iptables -X

    # Allow establishment of connections initialised by my outgoing packets
    iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

    # Accept anything on localhost
    iptables -A INPUT -i lo -j ACCEPT

    # Individual ports tcp
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT # SSH
    iptables -A INPUT -p tcp --dport 5432 -s 200.131.4.0/24 -j ACCEPT # Postgresql
    iptables -A INPUT -p tcp --dport 80 -s 200.131.4.0/24 -j ACCEPT # HTTP
    iptables -A INPUT -p tcp --dport 443 -s 200.131.4.0/24 -j ACCEPT # HTTPS
    iptables -A INPUT -p tcp --dport 8180 -s 200.131.4.0/24 -j ACCEPT

    # Drop everything else
    iptables -A INPUT -j DROP

    # Redirection rules (allowing forwarding from localhost)
    #iptables -t nat -A OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 8180

    # Redirection http
    #iptables -t nat -A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8180

### Iptables firewall: make changes permanent

P.S.: Need install the package `iptables-persistent`.

    sudo iptables-save > /etc/iptables/rules.v4
    sudo ip6tables-save > /etc/iptables/rules.v6

### Change the hostname

    sudo nano /etc/hostname
    sudo nano /etc/hosts
    sudo hostname [NEW_HOSTNAME]

### Configures a network interface

    ifconfig

### Configures a wireless interface

    iwconfig

### Detailed information about the wireless interface

    iwlist

### WPA/WPA2 and WPS testing

The following tool is a script that uses `aircrack-ng`, `reaver`, `bully` and others:

    wifite

To test a wordlist in a captured WPA handshake file:

    aircrack-ng -a 2 -w wordlist.txt handshake.cap

Or if you need GPU support (note that you need convert '.cap' to '.hccapx' file):

    hashcat -m 2500 handshake.hccapx wordlist.txt

### Gerenate a wordlist with numbers from 00000000 to 99999999

    crunch 8 8 0123456789 -o wordlist.txt

### Enable Wireshark capture

    sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

New method to enable it:

    sudo dpkg-reconfigure wireshark-common
    sudo usermod -a -G wireshark $USER

### Check active hosts on the network

    nmap -sP 192.168.0.0/24

### Check the open ports on a specific IP

    nmap 192.168.0.1

### Identify a host's operating system

    nmap -O 192.168.0.1

### List open ports from within a server

    netstat -ntlp

## Bluetooth

### List devices

    hcitool dev

### List devices informations

    hciconfig -a

### List devices (interactive with BlueZ)

    bluetoothctl
    (with command 'list')

## Sharing and security

### Share files with NFS

In the server, install the package `nfs-kernel-server`. And then:

    # Edit the file: /etc/exports
    /home/user    *(ro,sync,no_root_squash,no_subtree_check)

    # Run the command:
    sudo exportfs -a

    # Start the service:
    sudo /etc/init.d/nfs-kernel-server start

In the client, install the package `nfs-common`. And then:

    # Mount the directory:
    sudo mount 192.168.1.1:[SERVER_DIRECTORY] [DIRECTORY_TO_MOUNT]

### Share files with SSH

In the server, install the package `openssh-server`.

In the client, install the package `openssh-client` and `sshfs`. And then:

    # Mount the directory:
    sshfs [USERNAME]@[SERVER_IP_ADDRESS]:[SERVER_DIRECTORY] [DIRECTORY_TO_MOUNT]

    # You can umount the directory:
    fusermount -u [DIRECTORY_TO_MOUNT]

### Access terminal with SSH

In the server, install the package `openssh-server`.

In the client, install the package `openssh-client`. And then:

    # To connect:
    ssh [USERNAME]@[SERVER_IP_ADDRESS]

### Generating an SSH key

    ssh-keygen -t rsa -C "your_email@example.com"

Or also (for a key with 4096 bits):

    ssh-keygen -t rsa -b 4096 -C "your_email@example.com"

### Change SSH key password

    ssh-keygen -m 'PEM' -p -f ~/.ssh/id_rsa

### Import an SSH key

    mkdir ~/.ssh
    chmod 700 ~/.ssh
    chmod 600 ~/.ssh/id_rsa.pub
    chmod 600 ~/.ssh/id_rsa
    chmod 600 ~/.ssh/config
    ssh-add ~/.ssh/id_rsa

### SSH connection without password between client and server

Disclose public key generated by the client:

    ssh-copy-id -i ~/.ssh/id_rsa.pub [REMOTE_HOST]

## Encryption with GPG tool

### Generate GPG key

    gpg --full-generate-key

### List all GPG keys

    gpg --list-keys

### Export a GPG key

Text format:

    gpg --armor --output publickey.asc --export 10110DA4
    gpg --armor --output privatekey.asc --export-secret-keys 10110DA4

Binary format:

    gpg --output publickey.gpg --export 10110DA4
    gpg --output privatekey.gpg --export-secret-keys 10110DA4

### Import a GPG key

Text format:

    gpg --import privatekey.asc
    gpg --import publickey.asc

Binary format:

    gpg --import privatekey.gpg
    gpg --import publickey.gpg

### Sign a file with your GPG key

Output as 'binary format':

    gpg --sign my-doc.txt

Output as 'text format':

    gpg --clearsign my-doc.txt

### Encrypt a file with your GPG key (asymmetric encryption)

    gpg --encrypt my-doc.txt

### Encrypt a file with a password (symmetric encryption)

    gpg --symmetric --cipher-algo AES256 my-doc.txt

or:

    gpg --symmetric --for-your-eyes-only --cipher-algo AES256 my-doc.txt

### See details of a GPG file

    gpg --list-packets file.pgp

### Change GPG key password

    gpg --edit-key 10110DA4
    > passwd
    > save

## File manipulation

### Find duplicate files

List duplicate files (recursively):

    fdupes -r [DIRECTORY]

List duplicate files (recursively) and asks the user which file to delete:

    fdupes -r -d [DIRECTORY]

### Renames multiple files

Make a simulation:

    rename -n "s/[OLD_STRING]/[NEW_STRING]/" [FILES]

Performs the rename operation:

    rename "s/[OLD_STRING]/[NEW_STRING]/" [FILES]

### Set permissions recursively

    find . -type f -exec chmod 644 {} \;
    find . -type d -exec chmod 755 {} \;
    find . -iname "*.sh" -type f -exec chmod +x {} \;

### Delete empty directories

    find . -type d -empty -delete

### Find directories with write permission

    find . -type d -writable 2>/dev/null

### Change file modification date

    touch -t 200404281200 [FILES]

## Batch execution

### Run batch command with the find command

This example do: `ls 01.jpg` and then `ls 02.jpg`:

    find . -iname '*.jpg' -exec ls {} \;

This example do: `ls 01.jpg 02.jpg`:

    find . -iname '*.jpg' -exec ls {} +

### Run commands in parallel

Using `xargs` command (maximum number of processes):

    ls -1 *.svg | xargs --delimiter="\n" --max-procs=0 --replace="{}" 7z a -mx9 {}.7z {}

Using `xargs` command (4 processes):

    ls -1 *.svg | xargs --delimiter="\n" --max-procs=4 --replace="{}" 7z a -mx9 {}.7z {}

Or:

    find . -iname "*.svg" | xargs --delimiter="\n" --max-procs=4 --replace="{}" 7z a -mx9 {}.7z {}

Using `parallel` command (maximum number of processes):

    ls -1 *.svg | parallel "7z a -mx9 {.}.7z {}"

Using `parallel` command (4 processes):

    ls -1 *.svg | parallel --jobs 4 "7z a -mx9 {.}.7z {}"

### Create scripts that run commands in parallel

Follow the idea:

    command1 &
    command2 &
    wait
    command3 &
    command4 &
    wait

### Run a command every 3 seconds

P.S: If you don't specify the parameter `n`, the default is 2 seconds.

    watch -n 3 echo "Hello world!"

## File compression (archiving)

### Group files in 'tar' file

    tar -v -cf file.tar [FILES]

### Decompress 'tar.gz' files

    tar -xzf file.tar.gz

### Create a 'zip' file from the current directory

    zip -r file.zip .

## MP3 files

### Normalize audio from MP3 files

    mp3gain -r -c -s s  [FILENAME]

## MIDI files

### List MIDI ports

    aplaymidi -l

### Play MIDI file through the port

    aplaymidi --port 24:00 [FILENAME]

## Text manipulation

### Extract translation strings

    xgettext -d wxlame -s -o wxlame.po -k_ *.cpp *.h

### Search for strings within files recursively

Case insensitive:

    grep -r -i "STRING" [DIRECTORY]

Case sensitive:

    grep -r "STRING" [DIRECTORY]

With regex:

    grep -r -P "REGEX" [DIRECTORY]
    grep -r -i --include "*.h" --include "*.cpp" "STRING" [DIRECTORY]

### Replace strings in files

    find . -type f -iname "*.cpp" -exec sed -i -e "s|wxLame|wxMP3val|g" {} \;

### Create a frequency list of every word in a file (histogram of words)

    cat "text.txt" | tr ' :;,.()[]!?/' '\n' | tr '[:upper:]' '[:lower:]' | sed -r 's|^\w{1,3}$||' | sort | uniq -c | awk '{printf("%03d: %s\n", $1, $2)}' | sort -r

## Logs and system information

### Display multiple system informations

    uname -a > uname-a.log
    cat /proc/version_signature > version.log
    dmesg > dmesg.log
    lspci -vnvn > lspci-vnvn.log
    lsusb -v > lsusb-v.log

### Display hardware informations (generate a hardware report)

    sudo lshw -html > relatorio.html

### Display BIOS informations

    sudo dmidecode

## System administration

### Configure the keyboard layout

    sudo dpkg-reconfigure keyboard-configuration

To check the configuration, see the file `/etc/default/keyboard`.

### Configure the time zone

    sudo dpkg-reconfigure tzdata

### Clear all logs (truncate)

    sudo find /var/log/* -type f -iname "*log" -exec truncate -s 0 {} \;

### Find system files in the system database

    locate [FILENAME]

### Find a system command path

    which [COMMAND_NAME]

### View scheduled tasks on 'cron'

    crontab -l
    ls /etc/cron.hourly/
    ls /etc/cron.daily/
    ls /etc/cron.weekly/
    ls /etc/cron.monthly/

### See 'cron' (crontab) logs

    cat /var/log/syslog | grep -i "cron"
    zcat /var/log/syslog*gz | grep -i "cron"

### Generate a random password with 16 characters

    tr -dc A-Za-z0-9 </dev/urandom | head -c 16 ; echo

### Change the user password

    passwd [USER]

### Allow passwords less than 4 digits

Edit the file `/etc/pam.d/common-password` and make this change:

    # From
    password    [success=1 default=ignore]  pam_unix.so obscure sha512
    # To
    password    [success=1 default=ignore]  pam_unix.so obscure sha512 minlen=4

P.S.: To allow simple passwords, just remove the term "obscure" from the line above.

### List the 5 largest directories

    du -h . | sort -h -r | head -n 5

Ignore ".git" folder

    du -h . | sort -h -r | grep -v "\.git" | head -n 5

### List the 5 largest files

    find . -type f ! -path "*.git/*" -exec du -b {} + | sort -h -r | head -n 5

### Run 32-bit applications on Ubuntu

    sudo dpkg --add-architecture i386
    sudo apt-get update
    sudo apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386

### Clear bash history

    history -c && history -w && rm -f ~/.bash_history

### Creates a file with the history of all commands executed on all users' machines

    find "/home" -name ".bash_history" -exec cat {} \; 2>/dev/null 1>>"bash_history.txt"
    find "/root" -name ".bash_history" -exec cat {} \; 2>/dev/null 1>>"bash_history.txt"
    sed "s|[ \t]*$||;s|^[ \t]*||;s|^sudo ||g" "bash_history.txt" | sort -V -u >"bash_history_filtered.txt"

## System services

### Creating and manage a system service with 'systemd'

Create service the file:

    /etc/systemd/system/[SERVICE_NAME].service

Or also (for system packages):

    /usr/lib/systemd/system/[SERVICE_NAME].service

Enable and install the service:

    sudo systemctl enable [SERVICE_NAME]

Start the service:

    sudo systemctl [SERVICE_NAME] start

Check the service status:

    sudo systemctl status [SERVICE_NAME]

### Creating a scheduled service (timer) with 'systemd' for a user

Create the file `~/.config/systemd/user/my_service.service` with content:

    [Unit]
    Description=Run my script

    [Service]
    Type=simple
    ExecStart=/home/user/my_script.sh

Create the file `~/.config/systemd/user/my_service.timer` with content:

    [Unit]
    Description=Run my script every 30 seconds
    Requires=my_service.service

    [Timer]
    Unit=my_service.service
    OnUnitActiveSec=30s
    AccuracySec=1s

    [Install]
    WantedBy=timers.target

Enable and install the service:

    systemctl --user enable my_service.timer

Start the service:

    systemctl --user start my_service.timer

### Display a load time report for each service (systemd)

    systemd-analyze blame

Produce a image graph:

    systemd-analyze plot > image.svg

### Creating and manage a system service with 'System V init'

Create service the file:

    /etc/init.d/[SERVICE_NAME]

Enable and install the service (this command creates symbolic links at
`/etc/rc?.d/`):

    sudo update-rc.d [SERVICE_NAME] defaults

Start the service:

    sudo /etc/init.d/[SERVICE_NAME] start
    # Or also
    sudo service [SERVICE_NAME] start

If you would like to disable the service:

    sudo update-rc.d -f [SERVICE_NAME] disable

If you would like to remove the service:

    sudo update-rc.d -f [SERVICE_NAME] remove

Check the status of all services:

    sudo service --status-all

## Forensic techniques

### Recover deleted files

Analyzes the file system, has a wizard (comes with `testdisk` package):

    photorec

Recovers various types of files:

    foremost -T -v -t all -i /dev/sdb

Program based on the `foremost`.
You must configure the file `scalpel.conf` (based on the file `/usr/local/etc/foremost.conf`).

    scalpel /dev/sdb -c scalpel.conf -o DirOutput

### Erase data (anti-forensic)

Clean the disk by creating a large file in the free space:

    sfill -v [DIRECTORY]

Clean the disk by creating a large file in the free space (fast mode and filling it with zeros at the end):

    sfill -f -l -l -z -v [DIRECTORY]

Safely remove files:

    srm -v [FILE]

Clear the entire disk with zero values:

    sudo dd if=/dev/zero of=/dev/sdb bs=1M status=progress && sync

Clear the entire disk with random values (slower):

    sudo dd if=/dev/urandom of=/dev/sdb bs=1M status=progress && sync

### Search for data in the disk

Use the `xxd` to search strings:

    sudo xxd -c 40 /dev/sda | grep "string"

Use the `hexedit` to search strings and save parts:

    Tab: change from hex or ASCII
    Ctrl+Space: search
    Enter: goto the address
    Ctrl+Space: start selection
    Esc-W: copy
    Esc-Y: paste into a file
    Ctrl-X: save and exit
    Ctrl-C: exit without saving

## PDF files

### Encrypt PDF

    qpdf --encrypt "" "[PASSWORD]" 128 --accessibility=n --extract=n --print=none --modify=none -- file.pdf output.pdf

### Convert PDF to grayscale

    gs -q -dNOPAUSE -dBATCH -dSAFER -sDEVICE=pdfwrite -dEmbedAllFonts=true -dSubsetFonts=true -dAutoRotatePages=/None -sColorConversionStrategy=Gray -dProcessColorModel=/DeviceGray -sOutputFile=output.pdf input.pdf

### Replace strings in a PDF file

    qpdf --stream-data=uncompress input.pdf uncompressed.pdf
    sed -i "s/ORIGINALSTRING/NEWSTRING/g" uncompressed.pdf
    qpdf --stream-data=compress uncompressed.pdf output.pdf

### Remove strings in PDF's (recursively and in batch)

    LANG=en_US.iso88591
    find . -iname "*.pdf" ! -iname "*_compressed*" ! -iname "*_temp*" -type f -exec qpdf --stream-data=uncompress "{}" {}_temp.pdf \;
    find . -iname "*_temp.pdf" -type f -exec sed -i "s/ORIGINALSTRING///g" {} \;
    find . -iname "*_temp.pdf" ! -iname "*_compressed*" -type f -exec qpdf --stream-data=compress --linearize "{}" {}_compressed.pdf \;
    find . -iname "*_temp.pdf" -type f -exec rm "{}" \;

## Video files

### Video operations with 'ffmpeg'

H264 video suitable for Android smartphones with 320x480 resolution:

    ffmpeg -threads 4 -y -i "input.mp4" -c:v libx264 -preset slow -tune fastdecode -profile:v baseline -level 3.0 -crf 25.0 -filter:v "scale=iw*sar*min(480/(iw*sar)\,320/ih):ih*min(480/(iw*sar)\,320/ih)" -c:a libvo_aacenc -b:a 128k "output.mp4"

Video compatible with Windows XP without codecs (run with Windows Media Player):

    ffmpeg -threads 4 -y -i "input.mp4" -c:v wmv1 -b:v 450k -c:a wmav1 "output.wmv"

Video compatible with cell phones - 3gp:

    ffmpeg -threads 4 -y -i "input.mp4" -c:v h263 -r 25 -s qcif -c:a libopencore_amrnb -b:a 12.20k -ar 8000 -ac 1 "output.3gp"

Extract MP3 audio from video files:

    ffmpeg -threads 4 -y -i "input.mp4" -c:a libmp3lame -b:a 192k -ac 2 -vn "output.mp3"

Extract original audio from video files:

    ffmpeg -threads 4 -y -i "input.mp4" -vn -acodec copy audio.aac

Crop start and end of a video:

    ffmpeg -threads 4 -y -ss 50 -t 88 -i "input.mp4" -c:a copy -c:v copy "output.mp4"

Mix video and audio (also adds a 1.2 second audio delay):

    ffmpeg -threads 4 -y -i "input.mp4" -itsoffset 1.2 -i "audio.wav" -map 0:0 -map 1:0 -shortest "output.mp4"

Video for Instagram (mix audio and video):

    ffmpeg -threads 4 -y -i "input.mp4" -i "audio.wav" -c:v libx264 -preset slow -tune fastdecode -profile:v baseline -level 3.0 -crf 25.0 -r 30 -b:a 128k -filter:v "scale=iw*sar*min(1280/(iw*sar)\,720/ih):ih*min(1280/(iw*sar)\,720/ih)" -map 0:0 -map 1:0 -shortest "output.mp4"

## Versioning

### Untrack files already added to GIT repository based on .gitignore

Step 1: Remove everything from the repository:

    git rm -r --cached .

Step 2: Re add everything:

    git add .

Step 3: Commit:

    git commit -m ".gitignore fix"

### Advanced GIT commands

Compress the repository:

    git gc --aggressive

Pulls and fetches all tags:

    git pull --tags

Modify the last 10 commits:

    git rebase -i HEAD~10

Restores everything to the last commit:

    git reset --hard origin/master

### Add alias in GIT

    git config --global alias.co checkout
    git config --global alias.br branch
    git config --global alias.ci commit
    git config --global alias.st status

### Set other settings in GIT

    git config --global merge.tool meld
    git config --global diff.external meld

### Delete remote and local TAG in GIT

    git push --delete origin tagname
    git tag --delete tagname

### Clean the repository by deleting untracked and ignored files by .gitignore

    git clean -xdf

## Reverse engineering in executables

### Display information from an ELF executable

    readelf --all file.bin
    readelf -p .comment file.bin

### Display miscellaneous information about a file

    file file.binshared object dependencies
    mediainfo file.bin
    isoinfo -d -i file.iso

### List symbols from object files

    nm file.bin

### Remove binary symbols and other data from object files

    strip -s file.bin

### View an executable's shared object dependencies

    ld file.bin

### Extract strings in binary files

    strings --all --encoding=b file.bin > output_b.txt
    strings --all --encoding=B file.bin > output_B.txt
    strings --all --encoding=l file.bin > output_l.txt
    strings --all --encoding=L file.bin > output_L.txt
    strings --all --encoding=s file.bin > output_s.txt
    strings --all --encoding=S file.bin > output_S.txt

### Perform dissassembly of the object file (and executables)

    objdump -DF executable.bin > "output.txt"

### List calls to external libraries from an executable

    ltrace ./executable.bin

### List calls to system functions from an executable

    strace ./executable.bin
    strace -e trace=open,openat,close,read,write,connect,accept ./executable.bin

### Identify the process number using the filename

    fuser /bin/bash

### List all open files

    lsof

## Python

### Create virtual environment

    python3 -m venv [DIRECTORY]

### Install dependencies from a 'requirements.txt' file

    pip3 install --upgrade --requirement requirements.txt

### Install dependencies for the local user

    pip3 install [PACKAGE_NAME] --user

### Produce a binary executable from the code

    pyinstaller --onefile --windowed --icon=resource/icon-app.ico file.py

## Compilers

### Compiling and installing an application with the CMake

    mkdir build
    cd build
    cmake -DCMAKE_INSTALL_PREFIX:PATH=~/.local/ ..
    make
    sudo make install

### Compiling and installing an application with the Make

    mkdir build
    cd build
    ../configure --prefix=~/.local/
    make
    sudo make install

## Others

### Operations on XEN Server

List all VM's:

    xe vm-list

Open the interactive console:

    xsconsole

Start a VM:

    xe vm-start vm=[UUID]

Shutdown a VM:

    xe vm-shutdown vm=[UUID]

List all parameters of a VM:

    xe vm-param-list uuid=[UUID]

Changing the size of a VM's RAM:

    xe vm-param-set uuid=[UUID] memory-static-min=256MiB
    xe vm-param-set uuid=[UUID] memory-dynamic-min=256MiB
    xe vm-param-set uuid=[UUID] memory-static-max=512MiB
    xe vm-param-set uuid=[UUID] memory-dynamic-max=512MiB
    xe vm-memory-limits-set uuid=[UUID] static-min=16GiB dynamic-min=16GiB dynamic-max=16GiB static-max=16GiB

Change a VM's CPU amount:

    xe vm-param-set uuid=[UUID] platform:cores-per-socket=6
    xe vm-param-set uuid=[UUID] VCPUs-max=6
    xe vm-param-set uuid=[UUID] VCPUs-at-startup=6

### Secure passwords

Store:

    secret-tool store --label='Password for archives' archive myarchives

Read the stored password:

    secret-tool lookup archive myarchives

### Search for a configuration or value in 'gsettings'

    gsettings list-recursively | grep -i "some_value"

### Compile translation files

    msgfmt minha_traducao.po -o minha_traducao.mo

### Convert DER certificates to PEM (binary to text)

    openssl x509 -in input_cert.crt -inform der -outform pem -out output_cert.pem

### Redirect the audio from the microphone to the speaker

    pactl load-module module-loopback

### Make it possible to use USB in the virtualbox

Edit the file `/etc/group` and make this change:

    vboxusers:x:125:YOUR_USER

### Scanning an image (scanner)

    scanimage --mode Color --resolution 600 > file.ppm

### Copy the text from a tty5 terminal

    cat /dev/vcs5 > output.txt

### Change user directory paths (Xdg user directories)

Edit the file `~/.config/user-dirs.dirs`.

If you want change the language, you can also edit `~/.config/user-dirs.locale`.

### Define the default Java to be used

    sudo update-alternatives --config java

### Multi-connection multi-part file download

    aria2c -m 10 -s 10 -x 10 https://example.com/file.name

## Useful shell parameter expansions

| Parameter expansion         | Description                                          |
| --------------------------- | ---------------------------------------------------- |
| ${VARIABLE:start}           | Extract a substring                                  |
| ${VARIABLE:start:length}    | Extract a substring                                  |
| ${VARIABLE,,}               | Convert string to lowercase                          |
| ${VARIABLE^^}               | Convert string to uppercase                          |
| ${VARIABLE/pattern/string}  | String replace (for the first match)                 |
| ${VARIABLE//pattern/string} | String replace (for all matches)                     |
| ${VARIABLE/#pattern/string} | String replace (at the beginning)                    |
| ${VARIABLE/%pattern/string} | String replace (at the end)                          |
| ${#VARIABLE}                | Count the length of the variable                     |
| ${VARIABLE#pattern}         | Remove the shortest match (at the beginning)         |
| ${VARIABLE%pattern}         | Remove the shortest match (at the end)               |
| ${VARIABLE##pattern}        | Remove the longest match (at the beginning)          |
| ${VARIABLE%%pattern}        | Remove the longest match (at the end)                |
| ${VARIABLE:-value}          | Expand the value (if variable is unset)              |
| ${VARIABLE:=value}          | Set the value to the variable (if variable is unset) |

### Examples

| Parameter expansion | Description                                       |
| ------------------- | ------------------------------------------------- |
| ${VARIABLE##*.}     | Extract just the extension from a filename        |
| ${VARIABLE%.*}      | Extract just the name from a filename             |
| ${VARIABLE%/*}      | Extract dirname from a full path (or from a URL)  |
| ${VARIABLE##*/}     | Extract filename from a full path (or from a URL) |
