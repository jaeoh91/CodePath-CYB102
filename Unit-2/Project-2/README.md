# Project 2: Let's wget this Bread

## About
- We are provided with 3 attacks (as binary files), our goal is to use auditd to detect affected files and what each attack did

## Walkthrough
- set up a auditd rule to detect write & attribute modifications on the `protected_files` directory
- Added this line `-w /home/jaeoh91/project2-main/protected_files -p wa -k protected` to `sudo vim /etc/audit/rules.d/protected.rules` (new .rules file for organization)
- `-p` is the flag to specify which actions trigger a log, `w` is write and `a` is attribute modification
- `-k` is the flag to add a label string to the rule, logs triggered by this rule will contain the label string and allow us to filter logs under this rule

```
sudo systemctl restart auditd
sudo auditctl -l
```

### Pre-Attacks
- running `sudo ausearch -k protected` to search for auditd events under the `protected` key, we get one match where we created the rule (see `op=add_rule`)
```bash
jaeoh91@jaeoh91:/var/log/audit$ sudo ausearch -k protected
time->Sat Jun 20 21:44:02 2026
type=PROCTITLE msg=audit(1782006242.898:271): proctitle=2F7362696E2F617564697463746C002D52002F6574632F61756469742F61756469742E72756C6573
type=PATH msg=audit(1782006242.898:271): item=0 name="/home/jaeoh91/project2-main/protected_files" inode=921543 dev=fd:00 mode=040775 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1782006242.898:271): cwd="/"
type=SOCKADDR msg=audit(1782006242.898:271): saddr=100000000000000000000000
type=SYSCALL msg=audit(1782006242.898:271): arch=c000003e syscall=44 success=yes exit=1108 a0=3 a1=7ffffac1ea70 a2=454 a3=0 items=1 ppid=5220 pid=5240 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="auditctl" exe="/usr/sbin/auditctl" key=(null)
type=CONFIG_CHANGE msg=audit(1782006242.898:271): auid=4294967295 ses=4294967295 op=add_rule key="protected" list=4 res=1
```

- note to self, since I'm using a custom vm instead of codepath's vm, it appears codepath assumes all files are located @ `/home/codepath` instead of `/home/jaeoh91`. For this project, i js created symlinks so that when the attack scripts attempted to modify files in `/home/codepath`, they would actually modify the ones in `/home/jaeoh91`. Might have to look for a more long-term solution later

### attack-a
1. Running the attack
```bash
jaeoh91@jaeoh91:~/project2-main$ ./attack-a
Modifying a protected file at /home/codepath/project2-main/protected_files! ... hehe 
```

2. running `sudo ausearch -k protected`, new result:
```bash
time->Sat Jun 20 21:48:23 2026
type=PROCTITLE msg=audit(1782006503.961:313): proctitle="./attack-a"
type=PATH msg=audit(1782006503.961:313): item=1 name="/home/codepath/project2-main/protected_files/cloudia.txt" inode=921545 dev=fd:00 mode=0100664 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1782006503.961:313): item=0 name="/home/codepath/project2-main/protected_files/" inode=921543 dev=fd:00 mode=040775 ouid=1000 ogid=1000 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1782006503.961:313): cwd="/home/jaeoh91/project2-main"
type=SYSCALL msg=audit(1782006503.961:313): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff24d5cae0 a2=441 a3=1b6 items=2 ppid=2281 pid=5593 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="attack-a" exe="/home/jaeoh91/project2-main/attack-a" key="protected"
```
-> `attack-a` modifies `protected_files/cloudia.txt`

### attack-b
1. Running the attack
```bash
jaeoh91@jaeoh91:~/project2-main$ ./attack-b
Modifying a protected file at /home/codepath/project2-main/protected_files! ... hehe

Modifying a protected file at /home/codepath/project2-main/protected_files! ... hehe 
```
-> looks like there were two modifications now! lets catch them both

2. running `sudo ausearch -k protected`, new result:
```bash
----
time->Sat Jun 20 21:52:43 2026
type=PROCTITLE msg=audit(1782006763.144:320): proctitle="./attack-b"
type=PATH msg=audit(1782006763.144:320): item=1 name="/home/codepath/project2-main/protected_files/oakley.txt" inode=921549 dev=fd:00 mode=0100664 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1782006763.144:320): item=0 name="/home/codepath/project2-main/protected_files/" inode=921543 dev=fd:00 mode=040775 ouid=1000 ogid=1000 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1782006763.144:320): cwd="/home/jaeoh91/project2-main"
type=SYSCALL msg=audit(1782006763.144:320): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffc7ed1d410 a2=441 a3=1b6 items=2 ppid=2281 pid=5688 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="attack-b" exe="/home/jaeoh91/project2-main/attack-b" key="protected"
----
time->Sat Jun 20 21:52:43 2026
type=PROCTITLE msg=audit(1782006763.144:321): proctitle="./attack-b"
type=PATH msg=audit(1782006763.144:321): item=1 name="/home/codepath/project2-main/protected_files/squeaky.txt" inode=921551 dev=fd:00 mode=0100664 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1782006763.144:321): item=0 name="/home/codepath/project2-main/protected_files/" inode=921543 dev=fd:00 mode=040775 ouid=1000 ogid=1000 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1782006763.144:321): cwd="/home/jaeoh91/project2-main"
type=SYSCALL msg=audit(1782006763.144:321): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffc7ed1d510 a2=441 a3=1b6 items=2 ppid=2281 pid=5688 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="attack-b" exe="/home/jaeoh91/project2-main/attack-b" key="protected"
```
-> `attack-b` modifies `protected_files/oakley.txt` & `protected_files/squeaky.txt`


### attack-c
1. Running the attack
```bash
jaeoh91@jaeoh91:~/project2-main$ ./attack-c
Modifying a protected file at /home/codepath/project2-main/protected_files! ... hehe
```
-> back to one?

2. running `sudo ausearch -k protected`, new result:
```bash
time->Sat Jun 20 21:58:43 2026
type=PROCTITLE msg=audit(1782007123.943:328): proctitle="./attack-c"
type=PATH msg=audit(1782007123.943:328): item=1 name="/home/codepath/project2-main/protected_files/precipitation.csv" inode=921550 dev=fd:00 mode=0100664 ouid=1000 ogid=1000 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1782007123.943:328): item=0 name="/home/codepath/project2-main/protected_files/" inode=921543 dev=fd:00 mode=040775 ouid=1000 ogid=1000 rdev=00:00 nametype=PARENT cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1782007123.943:328): cwd="/home/jaeoh91/project2-main"
type=SYSCALL msg=audit(1782007123.943:328): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff6921f6d0 a2=441 a3=1b6 items=2 ppid=2281 pid=5768 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm="attack-c" exe="/home/jaeoh91/project2-main/attack-c" key="protected"
```

-> `attack-c` modifies `protected_files/precipitation.csv`