PREFIX=/usr/local
VERSION=2.0.2

DISTFILES=AUTHOR COPYING INSTALL README Makefile config user.auth main.go snowbox.8 debian init.d changelog snowbox.service usr.sbin.snowbox

all: snowbox

snowbox:
	go build -o snowbox main.go

foxbox:
	go build -o foxbox foxbox.go

clean:
	rm -f snowbox foxbox

install: install-bin install-conf install-doc
	@echo "Done."

install-bin: snowbox
	@echo "Installing binary into" $(DESTDIR)$(PREFIX)/sbin/snowbox
	@install -D -m 0755 -s snowbox $(DESTDIR)$(PREFIX)/sbin/snowbox

install-conf:
	@if [ ! -f "$(DESTDIR)/etc/snowbox/config" ]; then \
		echo "Installing config" $(DESTDIR)/etc/snowbox/config; \
		install -D -m 0600 config $(DESTDIR)/etc/snowbox/config; \
	fi
	@if [ ! -f "$(DESTDIR)/etc/snowbox/user.auth" ]; then \
		echo "Installing config" $(DESTDIR)/etc/snowbox/user.auth; \
		install -D -m 0600 user.auth $(DESTDIR)/etc/snowbox/user.auth; \
	fi
	@if [ ! -f "$(DESTDIR)/etc/init.d/snowbox" ]; then \
		echo "Installing" $(DESTDIR)/etc/init.d/snowbox; \
		install -D -m 0755 init.d/snowbox $(DESTDIR)/etc/init.d/snowbox; \
	fi
	@if [ ! -f "$(DESTDIR)/lib/systemd/system/snowbox.service" ]; then \
		echo "Installing "$(DESTDIR)/lib/systemd/system/snowbox.service; \
		install -D -m 0644 snowbox.service $(DESTDIR)/lib/systemd/system/snowbox.service; \
	fi

install-doc:
	@install -D -m 0644 snowbox.8 $(DESTDIR)$(PREFIX)/man/man8/snowbox.8

uninstall: uninstall-bin uninstall-doc
	@echo "Use make uninstall-conf to remove the configuration in /etc"

uninstall-bin:
	rm -f $(DESTDIR)$(PREFIX)/sbin/snowbox
	rm -f $(DESTDIR)/etc/init.d/snowbox

uninstall-doc:
	rm -f $(DESTDIR)$(PREFIX)/man/man8/snowbox.8

uninstall-conf:
	rm -rf /etc/snowbox
	rm -f /etc/init.d/snowbox
	rm -f /lib/systemd/system/snowbox.service

dist:
	mkdir snowbox-$(VERSION)
	cp -r $(DISTFILES) snowbox-$(VERSION)
	tar -czf snowbox-$(VERSION).tar.gz snowbox-$(VERSION)
	rm -rf snowbox-$(VERSION)

dist-binary: snowbox
	mkdir snowbox-$(VERSION)-amd64
	cp -r snowbox $(DISTFILES) snowbox-$(VERSION)-amd64
	tar -czf snowbox-$(VERSION)-amd64.tar.gz snowbox-$(VERSION)-amd64
	rm -rf snowbox-$(VERSION)-amd64

ssl-cert:
	openssl req -new -x509 -nodes -out snowbox.cert -keyout snowbox.key -days 365 -subj '/CN=localhost'
