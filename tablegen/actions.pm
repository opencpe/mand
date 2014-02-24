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
    );

END { }       # module clean-up code here (global destructor)

1;  # don't forget to return a true value from the file
