package actions;

use strict;
use warnings;

BEGIN {
    use Exporter();
    our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

    # set the version for version checking
    $VERSION     = 0.01;

    @ISA	 = qw(Exporter);
    @EXPORT      = qw(%actions);
    %EXPORT_TAGS = ( );
    @EXPORT_OK   = ( );
}
our @EXPORT_OK;

our %actions;

%actions = (
    "firewall"      => { include => "firewall.h",
			 comment => undef,
			 sel     => 2,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => [ "proxy", "scg_acl" ] },

    "proxy"	    => { include => "firewall.h",
			 comment => undef,
			 sel     => 2,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "zone"	    => { include => "session.h",
			 comment => undef,
			 sel     => 4,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => [ "firewall", "proxy", "scg_acl", "l3policy" ] },

    "scg_class"     => { include => undef,
			 comment => "/* meta action */",
			 sel     => 1,
			 pre     => undef,
			 action  => undef,
			 post    => undef,
			 chain   => [ "firewall", "l3policy" ] },

    "scg_acl"       => { include => "firewall.h",
			 comment => undef,
			 sel     => 2,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "wan_reconf"    => { include => "ifup.h",
			 comment => "/* WARN: look out for vaild selector length */",
			 sel     => 5,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => [ "httpd_reload" ] },

    "lan_reconf"    => { include => "ifup.h",
			 comment => "/* WARN: look out for vaild selector length */",
			 sel     => 3,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => [ "httpd_reload" ] },

    "rad_srv"       => { include => "radius.h",
			 comment => undef,
			 sel     => 6,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "zone_rad_srv"  => { include => "radius.h",
			 comment => undef,
			 sel     => 7,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "check_ntpd"    => { include => "ifup.h",
			 comment => "/* INFO: the selector will not be used during callback */",
			 sel     => 2,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "restart_syslog" => { include => "ifup.h",
			 comment => "/* INFO: the selector will not be used during callback */",
			 sel     => 3,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "restart_snmpd" => { include => "snmpd.h",
			 comment => "/* INFO: the selector will not be used during callback */",
			 sel     => 2,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "change_hname"  => { include => "ifup.h",
			 comment => undef,
			 sel     => 3,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "l3_reload"     => { include => "l3forward.h",
			 comment => undef,
			 sel     => 4,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "httpd_restart" => { include => "ifup.h",
			 comment => undef,
			 sel     => 1,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "httpd_reload"  => { include => "ifup.h",
			 comment => undef,
			 sel     => 1,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "relay"	    => { include => "dhcp.h",
			 comment => undef,
			 sel     => 2,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },
			
    "dev_rev_chng"  => { include => "ifup.h",
			 comment => undef,
			 sel     => 7,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "l3policy"      => { include => "session.h",
			 comment => undef,
			 sel     => 4,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    "l2tp_reconf"   => { include => "lng.h",
		         comment => "/* INFO: the selector will not be used during callback */",
		         sel     => 2,
		         pre     => undef,
		         action  => 1,
		         post    => undef,
		         chain   => undef },

    "l2tp_relay"    => { include => undef,
			 comment => "/* meta action: L2TP/LNG values also affecting DHCP relaying */",
			 sel     => 2,
			 pre     => undef,
			 action  => undef,
			 post    => undef,
			 chain   => [ "relay", "l2tp_reconf" ] },

    "clnt_timer_rearm" => { include => "client.h",
			 comment => undef,
			 sel     => 7,
			 pre     => undef,
			 action  => 1,
			 post    => undef,
			 chain   => undef },

    );

END { }       # module clean-up code here (global destructor)

1;  # don't forget to return a true value from the file
