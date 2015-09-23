This is an excercise in Linux kernel security programming. The goal is to restrict or prohibit forceful
process termination.

This is just a first approximation that proves the principle. The code works fine, but there's so much room for improvement.

I'm afraid I just touched the tip of an iceberg here. Things that I discovered while researching for this exercise
are endless, and it's easy to get a nervous breakdown while trying to satisfy my curiosity and fighting self-inflicted
sleep deprivation at the same time. Duh!

So, kill me? Kill me not? It's a game! Shall we?
I assume that you have Linux kernel sources installed.
```
make
insmod ./killmenot.ko proglist=/full/path/name_one,/full/path/name_two
```

Up to 16 programs may be specified.
Use `readlink -f /full/path/name` to get the actual program name if it's a symlink.

Start one of the specified programs. It's better if those are daemons. For instance, if you have Nginx installed like I do, the program to give to the module as an argument is `/usr/sbin/nginx`.

Start Nginx with a simple `sudo service nginx start`.
Then try to `kill -9 <PID of Nginx process>`.

See the process table with `ps ax`. See that Nginx is still there. See what's happened in `/var/log/syslog` or wherever your system logs kernel messages.
