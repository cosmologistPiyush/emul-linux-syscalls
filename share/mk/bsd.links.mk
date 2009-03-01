#	$NetBSD: bsd.links.mk,v 1.33 2009/03/01 09:42:41 isaki Exp $

.include <bsd.init.mk>

##### Basic targets
install:	linksinstall

##### Default values
LINKS?=
SYMLINKS?=

__linkinstall: .USE
	${_MKSHMSG_INSTALL} ${.TARGET}; \
	${_MKSHECHO} "${INSTALL_LINK} ${.ALLSRC} ${.TARGET}" && \
	${INSTALL_LINK} ${.ALLSRC} ${.TARGET}

##### Install rules
.PHONY:		linksinstall
linksinstall::	realinstall
.if !empty(SYMLINKS)
	@(set ${SYMLINKS}; \
	 while test $$# -ge 2; do \
		l=$$1; shift; \
		t=${DESTDIR}$$1; shift; \
		if  ttarg=`${TOOL_STAT} -qf '%Y' $$t` && \
		    [ "$$l" = "$$ttarg" ]; then \
			continue ; \
		fi ; \
		${_MKSHMSG_INSTALL} $$t; \
		${_MKSHECHO} ${INSTALL_SYMLINK} $$l $$t; \
		${INSTALL_SYMLINK} $$l $$t; \
	 done; )
.endif

.for _src _dst in ${LINKS}
_l:=${DESTDIR}${_src}
_t:=${DESTDIR}${_dst}

# Handle case conflicts carefully, when _dst occurs
# more than once after case flattening
.if ${MKUPDATE} == "no" || ${LINKS:tl:M${_dst:tl:Q}:[\#]} > 1
${_t}!		${_l} __linkinstall
.else
${_t}:		${_l} __linkinstall
.endif

linksinstall::	${_t}
.PRECIOUS:	${_t}
.endfor

configinstall:		configlinksinstall
.PHONY:			configlinksinstall
configlinksinstall::	configfilesinstall
.if !empty(CONFIGSYMLINKS)
	@(set ${CONFIGSYMLINKS}; \
	 while test $$# -ge 2; do \
		l=$$1; shift; \
		t=${DESTDIR}$$1; shift; \
		if  ttarg=`${TOOL_STAT} -qf '%Y' $$t` && \
		    [ "$$l" = "$$ttarg" ]; then \
			continue ; \
		fi ; \
		${_MKSHMSG_INSTALL} $$t; \
		${_MKSHECHO} ${INSTALL_SYMLINK} $$l $$t; \
		${INSTALL_SYMLINK} $$l $$t; \
	 done; )
.endif

.for _src _dst in ${CONFIGLINKS}
_l:=${DESTDIR}${_src}
_t:=${DESTDIR}${_dst}

# Handle case conflicts carefully, when _dst occurs
# more than once after case flattening
.if ${MKUPDATE} == "no" || ${CONFIGLINKS:tl:M${_dst:tl:Q}:[\#]} > 1
${_t}!		${_l} __linkinstall
.else
${_t}:		${_l} __linkinstall
.endif

configlinksinstall::	${_t}
.PRECIOUS:	${_t}
.endfor

.include <bsd.sys.mk>
