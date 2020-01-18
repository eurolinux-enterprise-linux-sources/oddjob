SUBDIRS = src scripts python sample tests doc
EXTRA_DIST = oddjob.spec oddjobconfig.dtd.in QUICKSTART TODO doc/oddjob.html

CONFIGURE_DEPENDENCIES = $(top_srcdir)/oddjob.spec

VERSION=$(shell grep ^Version: $(top_srcdir)/oddjob.spec | awk '{print $$NF}')
RELEASE=$(shell rpm -q --specfile $(top_srcdir)/oddjob.spec | awk '{print $$NF}')
TAG=oddjob-$(VERSION)
distdir=$(PACKAGE)-$(VERSION)

compare_versions:
	test $(VERSION) = `cat autoversion`
tag: compare_versions
	git tag $(TAG)

force-tag: compare_versions
	git tag -f $(TAG)

REPOSITORY=$(shell git config remote.origin.url 2> /dev/null || /bin/pwd)
ARCHIVEOUTDIR=$(shell cd $(top_srcdir) && pwd)

archive:
	tmpdir=`mktemp -d /tmp/make_archive_XXXXXX`;\
	if test -d "$$tmpdir" ; then \
		cd $$tmpdir;\
		git clone $(REPOSITORY);\
		cd $$tmpdir/$(PACKAGE);\
		git checkout $(TAG);\
		./autogen;\
		make dist;\
		mkdir -p $$tmpdir/rpm-build-top;\
		rpmbuild \
			--define "_topdir $$tmpdir/rpm-build-top" \
			--define "_sourcedir $$tmpdir/rpm-build-top" \
			--define "_specdir $$tmpdir/rpm-build-top" \
			--define "_builddir $$tmpdir/rpm-build-top" \
			--define "_srpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			-tb $(distdir).tar.gz;\
		cp -v $(distdir).tar.gz $(ARCHIVEOUTDIR)/;\
		rm -fr $$tmpdir;\
	fi
