mod_authz_signedurl.la: mod_authz_signedurl.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authz_signedurl.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_authz_signedurl.la
