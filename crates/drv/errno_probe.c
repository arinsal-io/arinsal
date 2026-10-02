/* Errno names known to erts/emulator/beam/erl_errno_str.c (errno_name and
 * errno_name_fallback), OTP-29.1.1, in source order. The first name compiled
 * for a value wins, as the collision guards in errno_name arrange. */
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

static int seen[4096];
static void add(int eno, const char *name) {
    if (eno <= 0 || eno >= 4096 || seen[eno]) return;
    seen[eno] = 1;
    printf("%d=", eno);
    for (const char *p = name; *p; p++) putchar(tolower((unsigned char)*p));
    putchar('\n');
}

int main(void) {
#ifdef ENO
    add(ENO, "ENO");
#endif
#ifdef E2BIG
    add(E2BIG, "E2BIG");
#endif
#ifdef EACCES
    add(EACCES, "EACCES");
#endif
#ifdef EADDRINUSE
    add(EADDRINUSE, "EADDRINUSE");
#endif
#ifdef EADDRNOTAVAIL
    add(EADDRNOTAVAIL, "EADDRNOTAVAIL");
#endif
#ifdef EAFNOSUPPORT
    add(EAFNOSUPPORT, "EAFNOSUPPORT");
#endif
#ifdef EAGAIN
    add(EAGAIN, "EAGAIN");
#endif
#ifdef EALREADY
    add(EALREADY, "EALREADY");
#endif
#ifdef EBADF
    add(EBADF, "EBADF");
#endif
#ifdef EBADMSG
    add(EBADMSG, "EBADMSG");
#endif
#ifdef EBUSY
    add(EBUSY, "EBUSY");
#endif
#ifdef ECANCELED
    add(ECANCELED, "ECANCELED");
#endif
#ifdef ECHILD
    add(ECHILD, "ECHILD");
#endif
#ifdef ECONNABORTED
    add(ECONNABORTED, "ECONNABORTED");
#endif
#ifdef ECONNREFUSED
    add(ECONNREFUSED, "ECONNREFUSED");
#endif
#ifdef ECONNRESET
    add(ECONNRESET, "ECONNRESET");
#endif
#ifdef EDEADLK
    add(EDEADLK, "EDEADLK");
#endif
#ifdef EDESTADDRREQ
    add(EDESTADDRREQ, "EDESTADDRREQ");
#endif
#ifdef EDOM
    add(EDOM, "EDOM");
#endif
#ifdef EDQUOT
    add(EDQUOT, "EDQUOT");
#endif
#ifdef EEXIST
    add(EEXIST, "EEXIST");
#endif
#ifdef EFAULT
    add(EFAULT, "EFAULT");
#endif
#ifdef EFBIG
    add(EFBIG, "EFBIG");
#endif
#ifdef EHOSTUNREACH
    add(EHOSTUNREACH, "EHOSTUNREACH");
#endif
#ifdef EIDRM
    add(EIDRM, "EIDRM");
#endif
#ifdef EILSEQ
    add(EILSEQ, "EILSEQ");
#endif
#ifdef EINPROGRESS
    add(EINPROGRESS, "EINPROGRESS");
#endif
#ifdef EINTR
    add(EINTR, "EINTR");
#endif
#ifdef EINVAL
    add(EINVAL, "EINVAL");
#endif
#ifdef EIO
    add(EIO, "EIO");
#endif
#ifdef EISCONN
    add(EISCONN, "EISCONN");
#endif
#ifdef EISDIR
    add(EISDIR, "EISDIR");
#endif
#ifdef ELOOP
    add(ELOOP, "ELOOP");
#endif
#ifdef EMFILE
    add(EMFILE, "EMFILE");
#endif
#ifdef EMLINK
    add(EMLINK, "EMLINK");
#endif
#ifdef EMSGSIZE
    add(EMSGSIZE, "EMSGSIZE");
#endif
#ifdef EMULTIHOP
    add(EMULTIHOP, "EMULTIHOP");
#endif
#ifdef ENAMETOOLONG
    add(ENAMETOOLONG, "ENAMETOOLONG");
#endif
#ifdef ENETDOWN
    add(ENETDOWN, "ENETDOWN");
#endif
#ifdef ENETRESET
    add(ENETRESET, "ENETRESET");
#endif
#ifdef ENETUNREACH
    add(ENETUNREACH, "ENETUNREACH");
#endif
#ifdef ENFILE
    add(ENFILE, "ENFILE");
#endif
#ifdef ENOBUFS
    add(ENOBUFS, "ENOBUFS");
#endif
#ifdef ENODATA
    add(ENODATA, "ENODATA");
#endif
#ifdef ENODEV
    add(ENODEV, "ENODEV");
#endif
#ifdef ENOENT
    add(ENOENT, "ENOENT");
#endif
#ifdef ENOEXEC
    add(ENOEXEC, "ENOEXEC");
#endif
#ifdef ENOLCK
    add(ENOLCK, "ENOLCK");
#endif
#ifdef ENOLINK
    add(ENOLINK, "ENOLINK");
#endif
#ifdef ENOMEM
    add(ENOMEM, "ENOMEM");
#endif
#ifdef ENOMSG
    add(ENOMSG, "ENOMSG");
#endif
#ifdef ENOPROTOOPT
    add(ENOPROTOOPT, "ENOPROTOOPT");
#endif
#ifdef ENOSPC
    add(ENOSPC, "ENOSPC");
#endif
#ifdef ENOSR
    add(ENOSR, "ENOSR");
#endif
#ifdef ENOSTR
    add(ENOSTR, "ENOSTR");
#endif
#ifdef ENOSYS
    add(ENOSYS, "ENOSYS");
#endif
#ifdef ENOTCONN
    add(ENOTCONN, "ENOTCONN");
#endif
#ifdef ENOTDIR
    add(ENOTDIR, "ENOTDIR");
#endif
#ifdef ENOTEMPTY
    add(ENOTEMPTY, "ENOTEMPTY");
#endif
#ifdef ENOTRECOVERABLE
    add(ENOTRECOVERABLE, "ENOTRECOVERABLE");
#endif
#ifdef ENOTSOCK
    add(ENOTSOCK, "ENOTSOCK");
#endif
#ifdef ENOTSUP
    add(ENOTSUP, "ENOTSUP");
#endif
#ifdef ENOTTY
    add(ENOTTY, "ENOTTY");
#endif
#ifdef ENXIO
    add(ENXIO, "ENXIO");
#endif
#ifdef EOPNOTSUPP
    add(EOPNOTSUPP, "EOPNOTSUPP");
#endif
#ifdef EOVERFLOW
    add(EOVERFLOW, "EOVERFLOW");
#endif
#ifdef EOWNERDEAD
    add(EOWNERDEAD, "EOWNERDEAD");
#endif
#ifdef EPERM
    add(EPERM, "EPERM");
#endif
#ifdef EPIPE
    add(EPIPE, "EPIPE");
#endif
#ifdef EPROTO
    add(EPROTO, "EPROTO");
#endif
#ifdef EPROTONOSUPPORT
    add(EPROTONOSUPPORT, "EPROTONOSUPPORT");
#endif
#ifdef EPROTOTYPE
    add(EPROTOTYPE, "EPROTOTYPE");
#endif
#ifdef ERANGE
    add(ERANGE, "ERANGE");
#endif
#ifdef EROFS
    add(EROFS, "EROFS");
#endif
#ifdef ESPIPE
    add(ESPIPE, "ESPIPE");
#endif
#ifdef ESRCH
    add(ESRCH, "ESRCH");
#endif
#ifdef ESTALE
    add(ESTALE, "ESTALE");
#endif
#ifdef ETIME
    add(ETIME, "ETIME");
#endif
#ifdef ETIMEDOUT
    add(ETIMEDOUT, "ETIMEDOUT");
#endif
#ifdef ETXTBSY
    add(ETXTBSY, "ETXTBSY");
#endif
#ifdef EWOULDBLOCK
    add(EWOULDBLOCK, "EWOULDBLOCK");
#endif
#ifdef EXDEV
    add(EXDEV, "EXDEV");
#endif
#ifdef ENOTBLK
    add(ENOTBLK, "ENOTBLK");
#endif
#ifdef ESOCKTNOSUPPORT
    add(ESOCKTNOSUPPORT, "ESOCKTNOSUPPORT");
#endif
#ifdef EPFNOSUPPORT
    add(EPFNOSUPPORT, "EPFNOSUPPORT");
#endif
#ifdef ESHUTDOWN
    add(ESHUTDOWN, "ESHUTDOWN");
#endif
#ifdef ETOOMANYREFS
    add(ETOOMANYREFS, "ETOOMANYREFS");
#endif
#ifdef EHOSTDOWN
    add(EHOSTDOWN, "EHOSTDOWN");
#endif
#ifdef EPROCLIM
    add(EPROCLIM, "EPROCLIM");
#endif
#ifdef EUSERS
    add(EUSERS, "EUSERS");
#endif
#ifdef EREMOTE
    add(EREMOTE, "EREMOTE");
#endif
#ifdef EBADRPC
    add(EBADRPC, "EBADRPC");
#endif
#ifdef ERPCMISMATCH
    add(ERPCMISMATCH, "ERPCMISMATCH");
#endif
#ifdef EPROGUNAVAIL
    add(EPROGUNAVAIL, "EPROGUNAVAIL");
#endif
#ifdef EPROGMISMATCH
    add(EPROGMISMATCH, "EPROGMISMATCH");
#endif
#ifdef EPROCUNAVAIL
    add(EPROCUNAVAIL, "EPROCUNAVAIL");
#endif
#ifdef EFTYPE
    add(EFTYPE, "EFTYPE");
#endif
#ifdef EAUTH
    add(EAUTH, "EAUTH");
#endif
#ifdef ENEEDAUTH
    add(ENEEDAUTH, "ENEEDAUTH");
#endif
#ifdef ENOATTR
    add(ENOATTR, "ENOATTR");
#endif
#ifdef EDOOFUS
    add(EDOOFUS, "EDOOFUS");
#endif
#ifdef ENOTCAPABLE
    add(ENOTCAPABLE, "ENOTCAPABLE");
#endif
#ifdef ECAPMODE
    add(ECAPMODE, "ECAPMODE");
#endif
#ifdef EINTEGRITY
    add(EINTEGRITY, "EINTEGRITY");
#endif
#ifdef EIPSEC
    add(EIPSEC, "EIPSEC");
#endif
#ifdef ENOMEDIUM
    add(ENOMEDIUM, "ENOMEDIUM");
#endif
#ifdef EMEDIUMTYPE
    add(EMEDIUMTYPE, "EMEDIUMTYPE");
#endif
#ifdef EPWROFF
    add(EPWROFF, "EPWROFF");
#endif
#ifdef EDEVERR
    add(EDEVERR, "EDEVERR");
#endif
#ifdef EBADEXEC
    add(EBADEXEC, "EBADEXEC");
#endif
#ifdef EBADARCH
    add(EBADARCH, "EBADARCH");
#endif
#ifdef ESHLIBVERS
    add(ESHLIBVERS, "ESHLIBVERS");
#endif
#ifdef EBADMACHO
    add(EBADMACHO, "EBADMACHO");
#endif
#ifdef ENOPOLICY
    add(ENOPOLICY, "ENOPOLICY");
#endif
#ifdef EQFULL
    add(EQFULL, "EQFULL");
#endif
#ifdef ECHRNG
    add(ECHRNG, "ECHRNG");
#endif
#ifdef EL2NSYNC
    add(EL2NSYNC, "EL2NSYNC");
#endif
#ifdef EL3HLT
    add(EL3HLT, "EL3HLT");
#endif
#ifdef EL3RST
    add(EL3RST, "EL3RST");
#endif
#ifdef ELNRNG
    add(ELNRNG, "ELNRNG");
#endif
#ifdef EUNATCH
    add(EUNATCH, "EUNATCH");
#endif
#ifdef ENOCSI
    add(ENOCSI, "ENOCSI");
#endif
#ifdef EL2HLT
    add(EL2HLT, "EL2HLT");
#endif
#ifdef EBADE
    add(EBADE, "EBADE");
#endif
#ifdef EBADR
    add(EBADR, "EBADR");
#endif
#ifdef EXFULL
    add(EXFULL, "EXFULL");
#endif
#ifdef ENOANO
    add(ENOANO, "ENOANO");
#endif
#ifdef EBADRQC
    add(EBADRQC, "EBADRQC");
#endif
#ifdef EBADSLT
    add(EBADSLT, "EBADSLT");
#endif
#ifdef EDEADLOCK
    add(EDEADLOCK, "EDEADLOCK");
#endif
#ifdef EBFONT
    add(EBFONT, "EBFONT");
#endif
#ifdef ENONET
    add(ENONET, "ENONET");
#endif
#ifdef ENOPKG
    add(ENOPKG, "ENOPKG");
#endif
#ifdef EADV
    add(EADV, "EADV");
#endif
#ifdef ESRMNT
    add(ESRMNT, "ESRMNT");
#endif
#ifdef ECOMM
    add(ECOMM, "ECOMM");
#endif
#ifdef ELOCKUNMAPPED
    add(ELOCKUNMAPPED, "ELOCKUNMAPPED");
#endif
#ifdef ENOTACTIVE
    add(ENOTACTIVE, "ENOTACTIVE");
#endif
#ifdef ENOTUNIQ
    add(ENOTUNIQ, "ENOTUNIQ");
#endif
#ifdef EBADFD
    add(EBADFD, "EBADFD");
#endif
#ifdef EREMCHG
    add(EREMCHG, "EREMCHG");
#endif
#ifdef ELIBACC
    add(ELIBACC, "ELIBACC");
#endif
#ifdef ELIBBAD
    add(ELIBBAD, "ELIBBAD");
#endif
#ifdef ELIBSCN
    add(ELIBSCN, "ELIBSCN");
#endif
#ifdef ELIBMAX
    add(ELIBMAX, "ELIBMAX");
#endif
#ifdef ELIBEXEC
    add(ELIBEXEC, "ELIBEXEC");
#endif
#ifdef ERESTART
    add(ERESTART, "ERESTART");
#endif
#ifdef ESTRPIPE
    add(ESTRPIPE, "ESTRPIPE");
#endif
#ifdef EDOTDOT
    add(EDOTDOT, "EDOTDOT");
#endif
#ifdef EUCLEAN
    add(EUCLEAN, "EUCLEAN");
#endif
#ifdef ENOTNAM
    add(ENOTNAM, "ENOTNAM");
#endif
#ifdef ENAVAIL
    add(ENAVAIL, "ENAVAIL");
#endif
#ifdef EISNAM
    add(EISNAM, "EISNAM");
#endif
#ifdef EREMOTEIO
    add(EREMOTEIO, "EREMOTEIO");
#endif
#ifdef ENOKEY
    add(ENOKEY, "ENOKEY");
#endif
#ifdef EKEYEXPIRED
    add(EKEYEXPIRED, "EKEYEXPIRED");
#endif
#ifdef EKEYREVOKED
    add(EKEYREVOKED, "EKEYREVOKED");
#endif
#ifdef EKEYREJECTED
    add(EKEYREJECTED, "EKEYREJECTED");
#endif
#ifdef ERFKILL
    add(ERFKILL, "ERFKILL");
#endif
#ifdef EHWPOISON
    add(EHWPOISON, "EHWPOISON");
#endif
    return 0;
}
