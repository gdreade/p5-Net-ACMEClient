package Net::ACMEClient;

use warnings;
use strict;
use Carp;
use Sys::Syslog qw(:standard :macros);
use Exporter;
use File::Spec;
use Config::Tiny;

use constant CHAL_DNS_01 => 'dns-01';

=head1 NAME

Net::ACMEClient - acme-client(1) integration methods

=head1 VERSION

Version 0.01

=cut

our @ISA = qw(Exporter);
our @EXPORT_OK = qw/error fatal/;


our $VERSION = '0.01';


=head1 SYNOPSIS

This module provides utility functions for the B<acme-client>(1)
Perl integration.

    use Net::ACMEClient;

    my $client = Net::ACMEClient->new(prog_name => __FILE__);
    $client->setup;
    ...
    $client->shutdown;

=head1 SUBROUTINES/METHODS

=head2 new

Constructor.

=cut

sub new {
    my $invocant = shift;
    my $self = bless({}, ref $invocant || $invocant);
    $self->init(@_);
    return $self;
}

# create accessors; do not put this in a method
for my $field(qw(config config_file log_stderr prog_name
                 syslog_facility use_syslog)) {
    my $slot = __PACKAGE__ . "::$field";
    no strict "refs";
    *$field = sub {
	my $self = shift;
	$self->{$slot} = shift if @_;
	return $self->{$slot};
    };
}

#
# Initialization code.  This gets called in the constructor after
# the bless is performed.
#
sub init {
    my $self = shift;

    # set default values
    $self->use_syslog(1);
    $self->syslog_facility(LOG_USER);
    $self->log_stderr(0);
    
    # accept initial values passed in constructor
    while (1) {
	my $name = shift;
	my $value = shift;

	defined($name) || last;
	if (defined($value)) {
	    $self->$name($value);
	}
    }

    # set prog_name, trimming and sanitizing it as necessary
    my $pn = $self->prog_name;
    defined($pn) || die "prog_name attribute must be set in constructor";
    if ($pn =~ m,([-_a-z0-9]+)$,) {
	$self->prog_name($1);
    } else {
	die "malformed program name $pn";
    }

    # set private members
}

=head2 setup

Performs setup operations.  Currently this is loading the configuration
file and initializing syslog if necessary.

=cut
    
sub setup {
    my $self = shift;

    $self->load_config;
    
    if ($self->use_syslog) {
	my $syslog_opts = 'pid';
	if ($self->log_stderr) {
	    $syslog_opts .= ',perror';
	}
	openlog($self->prog_name, $syslog_opts, $self->syslog_facility);
    }

    1;
}

=head2 shutdown

Perform shutdown operations

=cut

sub shutdown {
    my $self = shift;

    closelog();
    1;
}

# Locate the configuration file, load it, and pull out base values.
sub load_config {
    my $self = shift;

    my $config_file = $self->config_file;

    if (!defined($config_file) || (length($config_file) == 0)) {
	# try to deduce the location
	my $base = $self->prog_name . ".conf";
	my $locations = $self->conf_locations;
	foreach my $location (@$locations) {
	    my $c = $location . "/" . $base;
	    if ((-f $c) && ($c =~ m,^(.*)$,)) {
		$config_file = $1;
	    }
	}
    }    

    # too early for fatal()
    (-f $config_file)
	or die "configuration file " . $config_file . " does not exist";
    (-r $config_file)
	or die "configuration file " . $config_file .
	" exists but is not readable";

    my $config = Config::Tiny->read($config_file)
	or die "failed to read configuration file $config_file";
    $self->config($config);

    my $v = $config->{_}->{use_syslog};
    defined($v) && $self->use_syslog($v);

    1;
}

# internal method that gives us the set of possible locations for
# configuration files
sub conf_locations {
    my $self = shift;
    
    my $locations = [ '/etc', '/usr/local/etc' ];
    return $locations;
}

=head2 info(message)

This method prints an informational message to the appropriate channel.

=cut
    
sub info {
    my $self = shift;
    my $msg = shift;
    if (defined($msg) && (length($msg) > 0)) {
	if ($self->use_syslog) {
	    syslog(LOG_INFO, "%s", $msg);
	} else {
	    printf(STDERR "%s\n", $msg);
	}
    }
    1;
}

=head2 error(message)

This method prints an error message to the appropriate channel.

=cut
    
sub error {
    my $self = shift;
    my $msg = shift;
    if (defined($msg) && (length($msg) > 0)) {
	if ($self->use_syslog) {
	    syslog(LOG_ERR, "%s", $msg);
	} else {
	    printf(STDERR "%s\n", $msg);
	}
    }
    1;
}
    
=head2 fatal(message, exitval)

This method
prints an error message and exits the program with exit value exitval
(defaults to -1).

=cut

sub fatal {
    my $self = shift;
    my $msg = shift;
    my $exitval = shift;

    defined($msg) || ($msg = 'unspecified fatal error');
    defined($exitval) || ($exitval = -1);

    $self->error($msg);
    $self->shutdown;
    exit($exitval);
}    

=head2 do_via_system (command, arg[...])

This method is a front end to system(3). If the call is successful
this method will return 1.  Otherwise, it will print diagnostics via
syslog (if enabled) and return 0.

=cut
        
sub do_via_system {
    my $self = shift;
    
    (scalar(@_) > 0) || confess "no args to do_via_system";

    my $result = system(@_);
    if ($result == 0) {
        return 1;
    }
    my $exitval = $result >> 8;
    my $signum = $result & 127;
    my $gotcore = $result & 128;
    if ($signum != 0) {
	$self->error("@_ exited due to signal $signum");
    } else {
	$self->error("@_ exited with value $exitval");
    }
    if ($gotcore) {
        $self->error("(core dumped)");
    }
    return 0;
}


=head1 AUTHOR

Devin Reade, C<< <gdr at gno.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-acmeclient at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-ACMEClient>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::ACMEClient


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-ACMEClient>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-ACMEClient>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-ACMEClient>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-ACMEClient/>

=back


=head1 LICENSE AND COPYRIGHT

Copyright 2017 Devin Reade.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Net::ACMEClient
