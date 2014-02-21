dnl ##
dnl ##  Support for config.param files
dnl ##
dnl ##  configure.ac:
dnl ##    AC_CONFIG_PARAM(<file>)
dnl ##

AC_DEFUN([AC_CONFIG_PARAM],[
AC_DIVERT_PUSH(-1)
AC_ARG_WITH(param,[  --with-param=ID[[,ID,..]] load parameters from $1])
AC_DIVERT_POP()
AC_DIVERT_PUSH(NOTICE)
ac_prev=""
ac_param=""
if test -f $1; then
    ac_param="$1:common"
fi
for ac_option
do
    if test ".$ac_prev" != .; then
        eval "$ac_prev=\$ac_option"
        ac_prev=""
        continue
    fi
    case "$ac_option" in
        -*=*) ac_optarg=`echo "$ac_option" | sed 's/[[-_a-zA-Z0-9]]*=//'` ;;
           *) ac_optarg="" ;;
    esac
    case "$ac_option" in
        --with-param=* )
            case $ac_optarg in
                *:* )
                    ac_from=`echo $ac_optarg | sed -e 's/:.*//'`
                    ac_what=`echo $ac_optarg | sed -e 's/.*://'`
                    ;;
                * )
                    ac_from="$1"
                    ac_what="$ac_optarg"
                    ;;
            esac
            if test ".$ac_param" = .; then
                ac_param="$ac_from:$ac_what"
            else
                ac_param="$ac_param,$ac_from:$ac_what"
            fi
            ;;
    esac
done
if test ".$ac_param" != .; then
    # echo "loading parameters"
    OIFS="$IFS"
    IFS=","
    pconf="/tmp/autoconf.$$"
    echo "ac_options=''" >$pconf
    ac_from="$1"
    for ac_section in $ac_param; do
        changequote(, )
        case $ac_section in
            *:* )
                ac_from=`echo "$ac_section" | sed -e 's/:.*//'`
                ac_section=`echo "$ac_section" | sed -e 's/.*://'`
                ;;
        esac
        (echo ''; cat $ac_from; echo '') |\
        sed -e "1,/[    ]*[     ]*${ac_section}[        ]*{[    ]*/d" \
            -e '/[      ]*}[    ]*/,$d' \
            -e ':join' -e '/\\[         ]*$/N' -e 's/\\[        ]*\n[   ]*//' -e
 'tjoin' \
            -e 's/^[    ]*//g' \
            -e 's/^\([^-].*=.*\) IF \(.*\)$/if \2; then \1; fi/' \
            -e 's/^\(--.*=.*\) IF \(.*\)$/if \2; then ac_options="$ac_options \1
"; fi/' \
            -e 's/^\(--.*\) IF \(.*\)$/if \2; then ac_options="$ac_options \1";
fi/' \
            -e 's/^\(--.*=.*\)$/ac_options="$ac_options \1"/' \
            -e 's/^\(--.*\)$/ac_options="$ac_options \1"/' \
            >>$pconf
        changequote([, ])
    done
    IFS="$OIFS"
    . $pconf
    rm -f $pconf >/dev/null 2>&1
    if test ".[$]*" = .; then
        set -- $ac_options
    else
        set -- "[$]@" $ac_options
    fi
fi
AC_DIVERT_POP()
])dnl
