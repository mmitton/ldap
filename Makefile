include $(GOROOT)/src/Make.inc

TARG=github.com/mmitton/ldap
GOFILES=\
	bind.go\
	conn.go\
	control.go\
	filter.go\
	ldap.go\
	search.go\

include $(GOROOT)/src/Make.pkg
