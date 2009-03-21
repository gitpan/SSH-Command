#!/usr/bin/perl

use strict;
use warnings;
use Test::More;

BEGIN { plan tests => $ENV{test_ssh} ? 4 : 1; }

use_ok('SSH::Command');

exit unless $ENV{test_ssh};

ok( SSH::Command::get_uname_from_host_full_match(),    "Simple compare test"  );   
ok( SSH::Command::get_uname_from_host_regexp_verify(), "RegExp fail"          );
ok( SSH::Command::check_scp(),                         "SCP test"             );
