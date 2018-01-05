Snowbox
=======

Snowbox is a small and easy to setup POP3 server written in Go (2.0 and later).

Features
--------

* Written in a secure language
* APOP authentication
* SSL support
* IPv6
* Small codebase (800 lines)
* Easy setup (install, setup password, that's it)
* Apparmor profile for Linux included
* May be dusty and who-needs-pop3-anyway, but delivers every mail on my own server
and processes thousands of mails a day on my sysadmin junk mailbox at work. :)

What's up with the perl version?
--------------------------------

Snowbox has been rewritten in Go for version 2.0 which is the actively maintained release.
1.x will remain online as an alternative and may receive bugfixes, though there was nothing
to fix since 2010. It won the "Open Source Jahrbuch" hacking contest, a programming contest
where code with a maximum of 500 lines could be submitted.

Version 2.0 does not currently support the old custom maildrop locations.

Documentation
-------------

For installation instructions, please read the file INSTALL.
For configuration and operation instructions, please see the manpage.

System requirements
-------------------

To compile snowbox yourself you will need either the Go compiler from the official page,
golang.org or a package from your distribution (golang or gcc).

There may (or my not) be precompiled packages from your distribution. If you would like
to provide precompiled ones, I'm happy to mention them here.

License
-------

Snowbox is released under the GNU General Public License version 3. See the
file COPYING for details.
