##
##  Makefile -- Build procedure for sample namak Apache module
##  Autogenerated via ``apxs -n namak -g''.
##

builddir=.
top_srcdir=/usr/share/apache2
top_builddir=/usr/share/apache2
include /usr/share/apache2/build/special.mk

#   the used tools
APXS=apxs
APACHECTL=apachectl

#   additional defines, includes and libraries
#DEFS=-Dmy_define=my_value
#INCLUDES=-Imy/include/dir
SH_LIBS=-lriak_c_client-0.5

#   the default target
all: local-shared-build

#   install the shared object file into Apache 
install: install-modules-yes

#   cleanup
clean:
	-rm -f mod_namak.o mod_namak.lo mod_namak.slo mod_namak.la 

#   simple test
test: reload
	lynx -mime_header http://localhost/namak

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

