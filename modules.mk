mod_namak.la: mod_namak.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_namak.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_namak.la
