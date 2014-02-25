#!/usr/bin/perl

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

use strict;
use feature ":5.10";

use Data::Dumper;
use Text::CSV;

use File::Basename;
use lib dirname($0);
use actions;

sub gen_table {
    my $f = shift;
    my $h = shift;
    my $stubs = shift;
    my $level = shift;
    my $pos = shift;
    my $prfx = shift;
    my $fname;

    $fname = $prfx . '_' . $pos->{'name'};
    if ($pos->{'alias'}) {
	$prfx .= '_' . $pos->{'alias'};
    }

    if ($pos->{'instance'}) {
	$prfx .= '_' . $level;
	$level++;
    }

    foreach my $i (0 .. $#{$pos->{'fields'}}) {
	my $field = $pos->{'fields'}[$i];
	my $ref = \%{$pos->{'keys'}{$field}};

	if ($ref->{'type'} eq 'token' || $ref->{'type'} eq 'object') {
	    gen_table($f, $h, $stubs, $level, $ref, $prfx);
	}
    }

    if ($pos->{'type'} eq 'object') {
	my $idx = 1; 

	printf($f "const struct index_definition index%s =\n{\n", $fname);
	printf($f "\t/* type: %s, %s */\n", $pos->{'name'}, $pos->{'type'});
	printf($f "\t.idx\t= {\n");
	printf($f "\t\t{ .flags = IDX_UNIQUE, .type = T_INSTANCE },\n");
	foreach my $i (0 .. $#{$pos->{'fields'}}) {
	    my $field = $pos->{'fields'}[$i];
	    my $ref = \%{$pos->{'keys'}{$field}};

	    next if (!$ref->{'flags'}{'index'});

	    printf($f "\t\t{ ");
	    if ($ref->{'flags'}{'index'} == 2) {
		printf($f ".flags = IDX_UNIQUE, ");
	    }
	    printf($f ".type = T_%s, .element = cwmp_%s_%s },\n", uc($ref->{'type'}), $prfx, $ref->{'name'});
	    $idx++;
	}
	printf($f "\t},\n");
	printf($f "\t.size\t= %d\n", $idx);
	printf($f "};\n\n");
    }

    printf($f "const struct dm_table dm%s =\n{\n", $fname);
    printf($f "\tTABLE_NAME(\"%s\")\n", $pos->{'fq_name'});
    printf($f "\t.index\t= &index%s,\n", $fname) if ($pos->{'type'} eq 'object');
    printf($f "\t.size\t= %d,\n", $#{$pos->{'fields'}} + 1);
    printf($f "\t.table\t=\n\t{\n");

    foreach my $i (0 .. $#{$pos->{'fields'}}) {
	my $field = $pos->{'fields'}[$i];
	my $ref = \%{$pos->{'keys'}{$field}};

	printf($f "\t\t{\n\t\t\t/* %d */ \n\t\t\t.key\t= \"%s\",\n", $i + 1, $field);
	printf($h "#define cwmp_%s_%s\t\t%d\n", $prfx, $ref->{'name'}, $i + 1);

	my @flags = keys %{$ref->{'flags'}};
	if (@flags) {
	    printf($f "\t\t\t.flags\t= %s,\n", join(' | ', map( 'F_' . uc($_), @flags)));
	}

	printf($f "\t\t\t.action\t= DM_%s,\n", uc($ref->{'action'}));
	printf($f "\t\t\t.type\t= T_%s,\n", uc($ref->{'type'}));
	given($ref->{'type'}) {
	    when (['object', 'token']) {
		if ($ref->{'flags'}{'add'} || $ref->{'flags'}{'del'}) {
		    printf($f "\t\t\t.fkts.instance\t= {\n");
		    if ($ref->{'flags'}{'add'}) {
			printf($f "\t\t\t\t.add\t= add%s_%s,\n", $prfx, $ref->{'name'});
			printf($h "void add%s_%s(const struct dm_table *, dm_id, struct dm_instance *, struct dm_instance_node *);\n", $prfx, $ref->{'name'});
			printf($stubs "DMInstanceStub(add%s_%s);\n", $prfx, $ref->{'name'});
		    }
		    if ($ref->{'flags'}{'del'}) {
			printf($f "\t\t\t\t.del\t= del%s_%s\n", $prfx, $ref->{'name'});
			printf($h "void del%s_%s(const struct dm_table *, dm_id, struct dm_instance *, struct dm_instance_node *);\n", $prfx, $ref->{'name'});
			printf($stubs "DMInstanceStub(del%s_%s);\n", $prfx, $ref->{'name'});
		    }
		    printf($f "\t\t\t},\n");
		}

		printf($f "\t\t\t.u.t = {\n");
		printf($f "\t\t\t\t.table\t= &dm%s_%s,\n", $prfx, $ref->{'name'});
		if ($ref->{'max'}) {
		    printf($f "\t\t\t\t.max\t= %d,\n", $ref->{'max'});
		} else {
		    printf($f "\t\t\t\t.max\t= INT_MAX,\n");
		}
		printf($f "\t\t\t},\n");
	    }
	    when ('str') {
		if ($ref->{'max'}) {
		    printf($f "\t\t\t.u.l\t= {\n");
		    printf($f "\t\t\t\t.max\t= %d,\n", $ref->{'max'});
		    printf($f "\t\t\t},\n");
		}
	    }
	    when (['int', 'uint', 'int64', 'uint64']) {
		printf($f "\t\t\t.u.l\t= {\n");
		if ($ref->{'min'}) {
		    printf($f "\t\t\t\t.min\t= %d,\n", $ref->{'min'});
		} else {
		    given($ref->{'type'}) {
			when ('int')    { printf($f "\t\t\t\t.max\t= INT_MIN,\n"); }
			when ('int64')  { printf($f "\t\t\t\t.max\t= LLONG_MIN,\n"); }
		    }
		}
		if ($ref->{'max'}) {
		    printf($f "\t\t\t\t.max\t= %d,\n", $ref->{'max'});
		} else {
		    given($ref->{'type'}) {
			when ('int')    { printf($f "\t\t\t\t.max\t= INT_MAX,\n"); }
			when ('uint')   { printf($f "\t\t\t\t.max\t= UINT_MAX,\n"); }
			when ('int64')  { printf($f "\t\t\t\t.max\t= LLONG_MAX,\n"); }
			when ('uint64') { printf($f "\t\t\t\t.max\t= ULLONG_MAX,\n"); }
		    }
		}
		printf($f "\t\t\t},\n");  
	    }
	    when ('counter') {
		printf($f "\t\t\t.u.counter_ref\t= cwmp_%s_%s,\n", $prfx, $ref->{'counter_ref'});
	    }
	    when ('enum') {
		printf($f "\t\t\t.u.e\t= { .cnt = %d, .data = \"%s\" },\n",
		       $#{$ref->{'enum'}} + 1, join('\000', @{$ref->{'enum'}}));

		printf($h "typedef enum {\n");
		foreach my $j (0 .. $#{$ref->{'enum'}}) {
		    my $s =  $ref->{'enum'}[$j];
		    $s =~ tr/-\. \+/_/;
		    printf($h "\tcwmp__%s_%s_%s,\n", $prfx, $ref->{'alias'}, $s);
		}
		printf($h "} cwmp__%s_%s_e;\n", $prfx, $ref->{'alias'});
	    }
	}
	if ($ref->{'type'} ne 'counter') {
	    if ($ref->{'flags'}{'get'} || $ref->{'flags'}{'set'}) {
		    printf($f "\t\t\t.fkts.value\t= {\n");
		    if ($ref->{'flags'}{'get'}) {
			printf($f "\t\t\t\t.get\t= get%s_%s,\n", $prfx, $ref->{'name'});
			printf($h "DM_VALUE get%s_%s(const struct dm_value_table *, dm_id, const struct dm_element *, DM_VALUE);\n", $prfx, $ref->{'name'});
			printf($stubs "DMGetStub(get%s_%s);\n", $prfx, $ref->{'name'});
		    }
		    if ($ref->{'flags'}{'set'}) {
			printf($f "\t\t\t\t.set\t= set%s_%s\n", $prfx, $ref->{'name'});
			printf($h "int set%s_%s(struct dm_value_table *, dm_id, const struct dm_element *, DM_VALUE *, DM_VALUE);\n", $prfx, $ref->{'name'});
			printf($stubs "DMSetStub(set%s_%s);\n", $prfx, $ref->{'name'});
		    }
		    printf($f "\t\t\t},\n");
	    }
	}
	printf($f "\t\t},\n");
    }

    printf($f "\t}\n};\n\n");
}

sub get_node {
    my $pos = shift;
    my $comp = shift;
    my $next_is_instance = 0;

    foreach my $i (0 .. $#$comp) {
	if ($pos->{'keys'} eq undef) {
	    $pos->{'keys'} = {};
	    $pos->{'fields'} = [];
	}

	next if ($comp->[$i] =~ /\{(.)\}/);

	if ($pos->{'keys'}{$comp->[$i]} eq undef) {
	    $pos->{'keys'}{$comp->[$i]} = { 'name' => $comp->[$i]};
	    push(@{$pos->{'fields'}}, $comp->[$i]);
	}

	$pos = \%{$pos->{'keys'}{$comp->[$i]}};
	if ($next_is_instance) {
	    $pos->{'type'} = 'object';
	    $pos->{'instance'} = 'j';
	}
	$next_is_instance = 0;
    }
    return $pos;
}

my $fin;
my $csv;
my %igd;

if ($#ARGV != 0) {
    print "Usage: tokenizer.pl <file>\n";
    exit(1);
}

$csv = Text::CSV->new({binary => 1}) or die Text::CSV->error_diag();
open($fin, '<', $ARGV[0]) or die "Can't open $ARGV[1]: $!";
while (my $colref = $csv->getline($fin)) {
    #print Dumper($colref->[0]);
    next if (!(my @comp = split(/\./, $colref->[0])));

    if ($comp[0] eq '') {
	shift(@comp);
    }

#    next if ((my ($instance) = ($comp[$#comp] =~ /\{(.)\}/)));

    my $pos = get_node(\%igd, \@comp);

    $pos->{'flags'} = {};
    $pos->{'action'} = 'none';
    $pos->{'type'} = 'token';
    $pos->{'fq_name'} = join('.', @comp);
    if (!$pos->{'alias'}) {
	if ($colref->[1] ne '') {
	    $pos->{'alias'} = $colref->[1];
	} else {
	    $pos->{'alias'} = $pos->{'name'};
	}
    }

    my $min;
    my $max;
    ($min,$min,$max) = ($colref->[4] =~ /\[((-?\d*):)?(-?\d*)\]/);

    given($colref->[4]) {
	when ( /^unsignedInt64/i ) { $pos->{'type'} = 'uint64'; }
	when ( /^int64/i )         { $pos->{'type'} = 'int64'; }
	when ( /^unsignedInt/i )   { $pos->{'type'} = 'uint'; }
	when ( /^int/i )           { $pos->{'type'} = 'int'; }
	when ( /^bool/i )          { $pos->{'type'} = 'bool'; }
	when ( /^selector/i )      { $pos->{'type'} = 'selector'; }
	when ( /^string/i )        {
	    $pos->{'type'} = 'str';
	    if ((my ($len, $m) = (/\((\d+)(.?)\)/))) {
		$max = int($len);
		$max *= 1024 if ($m eq 'k' || $m eq 'K');
	    }
	}
	when ( /^ipv4/i )          { $pos->{'type'} = 'ipaddr4'; }
	when ( /^binary/i )        { $pos->{'type'} = 'binary'; }
	when ( /^base64/i )        { $pos->{'type'} = 'base64'; }
	when ( /^dateTime/i )      { $pos->{'type'} = 'date'; }
	when ( /^relticks/i )      { $pos->{'type'} = 'ticks'; }
	when ( /^absticks/i )      { $pos->{'type'} = 'ticks'; $pos->{'flags'}{'datetime'} = 1; }
	when ( /^enum/i )          {
	    $pos->{'type'} = 'enum';
	    my ($s) = ((/\((.*)\)/));
	    @{$pos->{'enum'}} = split(/,/, $s);
	}
	when ( /^pointer/i )       {
	    $pos->{'type'} = 'pointer';
	    $pos->{'flags'}{'acs_no_ntfy'} = 1;
	}
    }

    if ((my ($instance) = ($comp[$#comp] =~ /\{(.)\}/))) {
	$pos->{'type'} = 'object';
	$pos->{'instance'} = $instance;
    }

    if (my ($ref) = ($colref->[2] =~ /count\((.*)\)/)) {
	$pos->{'type'} = 'counter';
	$pos->{'counter_ref'} = $ref;
    }

    $pos->{'max'} = $max if ($max);
    $pos->{'min'} = $min if ($min);
    $pos->{'flags'}{'write'} = 1 if ($colref->[5] eq 'R' || $colref->[5] eq 'O' || $colref->[5] eq 'C');
    $pos->{'flags'}{'read'} = 1 if ($colref->[6] eq 'R' || $colref->[6] eq 'O' || $colref->[6] eq 'C');
    if ($pos->{'type'} ne 'object' &&
	$pos->{'type'} ne 'token' &&
	$pos->{'type'} ne 'counter') {
	$pos->{'flags'}{'get'} = 1 if ($colref->[2] eq '1');
	$pos->{'flags'}{'set'} = 1 if ($colref->[3] eq '1');
    }
    if ($pos->{'type'} eq 'object' ||
	$pos->{'type'} eq 'token') {
	$pos->{'flags'}{'add'} = 1 if ($colref->[2] eq '1');
	$pos->{'flags'}{'del'} = 1 if ($colref->[3] eq '1');
    }

    if ($colref->[7] ne '') {
	my @flags = split(//, $colref->[7]);

	$pos->{'flags'}{'system'} = 1   if ($flags[0] eq 'S');
	$pos->{'flags'}{'internal'} = 1 if ($flags[0] eq 'i');
	$pos->{'flags'}{'version'} = 1  if ($flags[0] eq 'V');

	$pos->{'flags'}{'index'} = 1    if ($flags[1] eq 'i');
	$pos->{'flags'}{'index'} = 2    if ($flags[1] eq 'u');

	$pos->{'flags'}{'acs_ntfy'} = 1    if ($flags[2] eq 'F');
	$pos->{'flags'}{'acs_no_ntfy'} = 1 if ($flags[2] eq 'N');

	$pos->{'flags'}{'map_id'} = 1   if ($flags[3] eq 'M');
    }
 
    if ($pos->{'type'} eq 'object' ||
	$pos->{'type'} eq 'token') {
	delete($pos->{'flags'}{'write'});
	delete($pos->{'flags'}{'read'});
    }

    $pos->{'action'} = $colref->[8] if ($actions{$colref->[8]});
}

close($fin);

my $f;
my $h;
my $stubs;

open($f, '>', 'p_table.c') or die "Can't create p_table.c: $!";
printf($f "/* This Source Code Form is subject to the terms of the Mozilla Public\n" .
          " * License, v. 2.0. If a copy of the MPL was not distributed with this\n" .
          " * file, You can obtain one at http://mozilla.org/MPL/2.0/. */\n\n");
printf($f "/*\n" .
          " * WARNING: This file has been autogenerated by tablegen/tokenizer.pl\n" .
          " *\n" .
          " *            !!! DO NOT MODIFY MANUALLY !!!\n" .
          " */\n\n");
printf($f "#include <stdlib.h>\n\n");
printf($f "#include <limits.h>\n\n");
printf($f "#include \"dm.h\"\n");
printf($f "#include \"dm_token.h\"\n");
printf($f "#include \"p_table.h\"\n\n");

open($h, '>', 'p_table.h') or die "Can't create p_table.h: $!";
printf($h "/* This Source Code Form is subject to the terms of the Mozilla Public\n" .
          " * License, v. 2.0. If a copy of the MPL was not distributed with this\n" .
          " * file, You can obtain one at http://mozilla.org/MPL/2.0/. */\n\n");
printf($h "/*\n" .
          " * WARNING: This file has been autogenerated by tablegen/tokenizer.pl\n" .
          " *\n" .
          " *            !!! DO NOT MODIFY MANUALLY !!!\n" .
          " */\n\n");
printf($h "#ifndef __P_TABLE_H\n");
printf($h "#define __P_TABLE_H\n\n");

open($stubs, '>', 'p_table_stubs.c') or die "Can't create p_table_stubs.c: $!";
printf($stubs "/* This Source Code Form is subject to the terms of the Mozilla Public\n" .
              " * License, v. 2.0. If a copy of the MPL was not distributed with this\n" .
              " * file, You can obtain one at http://mozilla.org/MPL/2.0/. */\n\n");
printf($stubs "/*\n" .
              " * WARNING: This file has been autogenerated by tablegen/tokenizer.pl\n" .
              " *\n" .
              " *            !!! DO NOT MODIFY MANUALLY !!!\n" .
              " */\n\n");
printf($stubs "#include <stdlib.h>\n\n");
printf($stubs "#include <limits.h>\n\n");
printf($stubs "#include \"dm.h\"\n");
printf($stubs "#include \"dm_token.h\"\n");
printf($stubs "#include \"dm_action_table.h\"\n");
printf($stubs "#include \"dm_fkt_stubs.c\"\n");
printf($stubs "#include \"p_table.h\"\n\n");

#print Dumper(\%igd);
$igd{'name'} = 'root';
$igd{'fq_name'} = '.';

gen_table($f, $h, $stubs, 'i', \%igd, '');

close($f);
printf($h "\n#endif\n");
close($h);
close($stubs);

