# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

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
    "ntp"           => { include => undef,
			 comment => undef,
			 sel     => 2,
			 pre     => undef,
			 action  => undef,
			 post    => undef,
			 chain   => undef },
    );

END { }       # module clean-up code here (global destructor)

1;  # don't forget to return a true value from the file
