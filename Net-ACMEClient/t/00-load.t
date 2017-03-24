#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Net::ACMEClient' ) || print "Bail out!
";
}

diag( "Testing Net::ACMEClient $Net::ACMEClient::VERSION, Perl $], $^X" );
