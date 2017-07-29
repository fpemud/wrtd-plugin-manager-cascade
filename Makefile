PACKAGE_VERSION=0.0.1
prefix=/usr
plugin=manager_cascade

all:

clean:
	fixme

install:
	install -d -m 0755 "$(DESTDIR)/$(prefix)/lib/wrtd/plugins"
	cp -r $(plugin) "$(DESTDIR)/$(prefix)/lib/wrtd/plugins"
	find "$(DESTDIR)/$(prefix)/lib/wrtd/plugins/$(plugin)" -type f | xargs chmod 644
	find "$(DESTDIR)/$(prefix)/lib/wrtd/plugins/$(plugin)" -type d | xargs chmod 755

uninstall:
	rm -rf "$(DESTDIR)/$(prefix)/lib/wrtd/plugins/$(plugin)"

.PHONY: all clean install uninstall
