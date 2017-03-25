package Net::ACMEClient::DNS;

use warnings;
use strict;
use Carp;
use File::Copy;
use Net::DNS::Resolver;
use Sys::Syslog qw(:standard :macros);
use Exporter;

use constant DEFAULT_QUERY_PAUSE => 2;
use constant DEFAULT_PROPAGATION_TIMEOUT => 120;

=head1 NAME

Net::ACMEClient::DNS - DNS integration module for acme-client(1)

=head1 VERSION

Version 0.01

=cut

our @ISA = qw(Exporter);
our @EXPORT_OK = qw(acme_challenge_rr_name encode_challenge untaint_fqdn);

our $VERSION = '0.01';

=head1 SYNOPSIS

This module provides utility code for integrating B<acme-client>(1)
with a DNS infrastructure.

    use Net::ACMEClient::DNS qw/acme_challenge_rr_name untaint_fqdn/;

    # you should use the IPs of the appropriate public
    # authoritive nameservers here
    $nameservers = [ '192.168.1.20', '192.168.2.20' ];

    my $dns = Net::ACMEClient::DNS->new();
    $dns->wait_for_challenge_propagation('www.example.com', $challenge,
                                         undef, $nameservers)
       || die "challenges failed to appear on DNS servers within the "
            . "configured timeout";


    # this would be "_acme-challenge.www.example.com."
    my $record_name = acme_challenge_rr_name('www.example.com');

    my $untainted = untaint_fqdn($tainted_fully_qualified_domain_name);
    
=head1 ATTRIBUTES

The following attributes may be provided to the B<new> method:

=head2 debug_queries

If set, then the debug flag will be provided to the Net::DNS modules
to aid in debugging.  See L<Net::DNS::Resolver>.

=head2 query_pause

When B<wait_for_challenge_propagation> is testing nameservers and there is
at least one nameserver that doesn't yet have the expected record, the
method will sleep this long before starting the next round of queries
against such nameservers.

By default this is 120 seconds.

=head2 use_syslog

If set, then diagnostics will be logged via syslog.  This module does
not perform any syslog initializations.

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
for my $field(qw(debug_queries query_pause use_syslog)) {
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
    $self->debug_queries(0);
    $self->query_pause(DEFAULT_QUERY_PAUSE);
    $self->use_syslog(0);
    
    # accept initial values passed in constructor
    while (1) {
	my $name = shift;
	my $value = shift;

	defined($name) || last;
	if (defined($value)) {
	    $self->$name($value);
	}
    }

    # override problematic values
    my $pause = $self->query_pause;
    if (($pause < 1) || ($pause > 30)) {
	$self->query_pause(DEFAULT_QUERY_PAUSE);
    }

    # set private members
}

=head2 acme_challenge_rr_name(fqdn)

This global method
returns the name of the DNS RR record to use for ACME challenges 
for the given fully qualified domain name.

=cut

sub acme_challenge_rr_name {
    my $fqdn = shift;

    defined($fqdn) || croak "fqdn was not defined";
    ($fqdn eq '') && croak "fqdn cannot be empty";

    return "_acme-challenge." . $fqdn . ".";
}

=head2 encode_challenge($challenge)

This global method encodes a challenge as required by the ACME protocol
by computing the SHA256 hash of the challenge, and then encoding the
hash in a URL-safe variant of Base64 encoding.

Returns the encoded challenge.

=cut

sub encode_challenge {
    my $challenge = shift;

    defined($challenge) || croak "challenge was not defined";

    my $encoded = sha256_base64($challenge);
    $encoded =~ s,\+,-,g;
    $encoded =~ s,/,_,g;
    return $encoded;
}

=head2 expect_txt(resolver, name, record_value)

Using B<resolver>, look up a DNS TXT record with the name B<name>
and verify that it has the expected value of B<record_value>.

Returns 1 if the expected record was found, undef otherwise.

=cut

sub expect_txt {
    my $self = shift;
    my $resolver = shift;
    my $name = shift;
    my $record_value = shift;

    my $packet = $resolver->query($name, 'TXT');
    defined($packet) || return undef;

    my @answers = $packet->answer;
    foreach my $answer (@answers) {
	if (uc($answer->type) eq 'TXT') {
	    my $txt = $answer->txtdata;
	    defined($txt) || die "internal error: txtdata was undef";

	    if ($txt eq $record_value) {
		return 1;
	    }
	}
    }
    
    return undef;
}

=head2 untaint_fqdn

This static method
takes a single argument that should be a DNS fully qualfied domain
name.  Verifies that it is of the proper form, untaints it, and
returns the lowercase version.  Returns undef if any checks fail,
or if the original value was undef.

=cut
        
sub untaint_fqdn {
    my $value = shift;

    if (defined($value)) {
	if ($value =~ m,^\s*([a-z0-9][-a-z0-9\.]*)\s*$,i) {
	    my $fqdn = $1;
	    return lc($fqdn);
	}
    }
    return undef;
}


=head2 wait_for_challenge_propagation(fqdn, challenge, timeout, nameservers)

Wait for an ACME challenge B<challenge> based on B<fqdn> to appear on
a set of nameservers.  B<nameservers> can be a single nameserver specification
(an IP), or an arrayref of such specifications.

This method will wait up to B<timeout> seconds, total, for the answer to 
appear on all specified nameservers.  If B<timeout> is undef, then a default
of 120 seconds is used.

Returns 1 on success, undef if the challenge is not seen on at least one
of the nameservers within the timeout period.

Diagnostics will be logged if $self->use_syslog has been set.

=cut

sub wait_for_challenge_propagation {
    my $self = shift;
    my $fqdn = shift;
    my $challenge = shift;
    my $timeout = shift;
    my $nameserver_arg = shift;

    defined($fqdn) || croak "fqdn was not defined";
    defined($challenge) || croak "challenge was not defined";
    defined($timeout) || ($timeout = DEFAULT_PROPAGATION_TIMEOUT);

    my $nameservers = [];
    if (defined($nameserver_arg)) {
	my $r = ref($nameserver_arg);
	if ($r eq '') {
	    push(@$nameservers, ($nameserver_arg)) if ($nameserver_arg ne '');
	} elsif ($r = 'ARRAY') {
	    push(@$nameservers, @$nameserver_arg);
	} else {
	    croak "the fourth argument to wait_for_challenge_propagation "
		. "must be a nameserver IP or an arrayref containing "
		. "nameserver IPs";
	}
    } else {
	die "lookup of nameservers not yet implemented";
    }

    if (scalar(@$nameservers) < 1) {
	croak "no nameservers were specified";
    }

    # set up the resolvers, one per nameserver
    my %resolvers_by_nameserver;
    foreach my $ns (@$nameservers) {
	my $resolver = Net::DNS::Resolver->new(nameservers => [$ns],
					       recurse => 0,
					       dnssec => 1,
					       debug => $self->debug_queries);
	$resolvers_by_nameserver{$ns} = $resolver;
    }

    my $name = acme_challenge_rr_name($fqdn);

    my $start_time = time;
    my $max_end_time = $start_time + $timeout;

    while (scalar(@$nameservers) > 0) {
	# complete is a hash of $nameservers indices by nameserver 
	my %complete;
	my $index = 0;
	foreach my $ns (@$nameservers) {
	    my $resolver = $resolvers_by_nameserver{$ns};
	    defined($resolver) || die "internal error, no resolver for $ns";

	    my $ret = $self->expect_txt($resolver, $name, $challenge);
	    if ($ret) {
		syslog(LOG_DEBUG, "found record in %s", $ns)
		    if ($self->use_syslog);
		$complete{$ns} = $index;
	    }
	    $index++;
	}

	foreach my $ns (keys(%complete)) {
	    $index = $complete{$ns};
	    splice(@$nameservers, $index, 1);
	}

	# if we still have nameservers that didn't have the correct
	# answers, pause briefly before asking again (thus allowing
	# the changes to propagate)
	if (scalar(@$nameservers) > 0) {

	    my $current_time = time;
	    if ($current_time > $max_end_time) {
		# time exceeded
		syslog(LOG_ERR, "the expected challenge failed to appear "
		       . "on the configured nameservers within the configured "
		       . "timeout (%ss)", $timeout) if ($self->use_syslog);
		foreach my $ns (@$nameservers) {
		    syslog(LOG_ERR,
			   "challenge not seen on nameserver %s", $ns)
			if ($self->use_syslog);
		}
		return undef;
	    }
	    syslog(LOG_DEBUG, "pausing %d seconds to wait for query "
		   . "propagation", $self->query_pause) if ($self->use_syslog);
	    sleep($self->query_pause);
	}

    }

    # success
    return 1;
}

=head1 SEE ALSO

B<acme-client>(1)

=head1 AUTHOR

Devin Reade, C<< <gdr at gno.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-acmeclient-dns-zoneeditor at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-ACMEClient-DNS>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::ACMEClient::DNS


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-ACMEClient-DNS>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-ACMEClient-DNS>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-ACMEClient-DNS>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-ACMEClient-DNS/>

=back


=head1 LICENSE AND COPYRIGHT

Copyright 2017 Devin Reade.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Net::ACMEClient::DNS
