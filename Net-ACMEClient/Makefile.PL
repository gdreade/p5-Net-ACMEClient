use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::ACMEClient',
    AUTHOR              => q{Devin Reade <gdr@gno.org>},
    VERSION_FROM        => 'lib/Net/ACMEClient.pm',
    ABSTRACT_FROM       => 'lib/Net/ACMEClient.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
	'Net::DNS' => 0,
	'Net::DNS::SEC' => 0,
    },
    INST_BIN            => 'bin',
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Net-ACMEClient-*' },
);
