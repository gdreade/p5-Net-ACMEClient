package Net::ACMEClient::DNS;

use warnings;
use strict;
use Carp;
use File::Copy;
use Net::DNS::Resolver;
use Sys::Syslog qw(:standard :macros);
use Exporter;
use Digest::SHA qw(sha256_base64);

use constant DEFAULT_QUERY_PAUSE => 2;
use constant DEFAULT_PROPAGATION_TIMEOUT => 120;

use constant IPV4_ONLY => 4;
use constant IPV6_ONLY => 6;

=head1 NAME

Net::ACMEClient::DNS - DNS integration module for acme-client(1)

=head1 VERSION

Version 0.01

=cut

our @ISA = qw(Exporter);
our @EXPORT_OK = qw/acme_challenge_rr_name encode_challenge untaint_fqdn
                   IPV4_ONLY IPV6_ONLY DEFAULT_PROPAGATION_TIMEOUT/;

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

    # if you don't provide nameservers, the module will figure them out
    $dns->wait_for_challenge_propagation('www.example.com', $challenge)
       || die "challenges failed to appear on DNS servers within the "
            . "configured timeout";

    # this would be "_acme-challenge.www.example.com."
    my $record_name = acme_challenge_rr_name('www.example.com');

    my $untainted = untaint_fqdn($tainted_fully_qualified_domain_name);

    # put it into a form that hides the key
    my $suitable_for_dns = encode_challenge($raw_challenge_from_acme_client);

=head1 CONSTANTS

=head2 IPV4_ONLY

This value is used to indicate that the caller is interested in IPv4 answers,
only.

=head2 IPV6 ONLY

This value is used to indicate that the caller is interested in IPv6 answers,
only.

=head1 ATTRIBUTES

The following attributes may be provided to the B<new> method:

=head2 debug_queries

If set, then the debug flag will be provided to the Net::DNS modules
to aid in debugging.  See L<Net::DNS::Resolver>.

=head2 four_or_six

If set to IPV4_ONLY, then only DNS A records will be queried.
If set to IPV6_ONLY, then only DNS AAAA records will be queried.

By default this is undef, so both A and AAAA queries will be used.

=head2 query_pause

When B<wait_for_challenge_propagation> is testing nameservers and there is
at least one nameserver that doesn't yet have the expected record, the
method will sleep this long before starting the next round of queries
against such nameservers.

By default this is 120 seconds.

=head2 use_dnssec

If set, then the Net::DNS::Resolver B<dnssec> flag will be set such
that DNSSEC validation will be performed if available.  By default it 
is set.

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
for my $field(qw(debug_queries four_or_six query_pause
                 use_dnssec use_syslog)) {
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
    $self->use_dnssec(1);
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

=head2 fqdn_to_ip(fqdn, resolver)

Looks up fqdn and returns an arrayref of IPs associated with that name.
If fqdn looks like an IP, it will be returned directly in the arrayref.
Otherwise, address records will be looked up for the given fqdn.

If resolver is undef, then this method will use a new resolver based on
the system default recursive resolver.

If four_or_six is the number 4, then only 'A' records will be queried.


=cut
    
sub fqdn_to_ip {
    my $self = shift;
    my $fqdn = shift;
    my $resolver = shift;

    defined($fqdn) || croak "fqdn is undefined";

    my $four_or_six = $self->four_or_six;
    my $result = [];

    if ($fqdn =~ m,^([0-9\.]+)$,) {
	# it looks like an IPv4 address already; just use it
	push(@$result, ($1))
	    unless (defined($four_or_six) && ($four_or_six == IPV6_ONLY));
	return $result;
    } elsif ($fqdn =~ m,^([a-f0-9]+:[:a-f0-9]+)$,i) {
	# it looks like an IPv6 address already; just use it
	push(@$result, ($1))
	    unless (defined($four_or_six) && ($four_or_six == IPV4_ONLY));
	return $result;
    }

    if (!defined($resolver)) {
	$resolver = Net::DNS::Resolver->new(recurse => 1,
					    dnssec => $self->use_dnssec,
					    debug => $self->debug_queries);
    }

    if (!defined($four_or_six) || ($four_or_six == IPV4_ONLY)) {
	my $subresult = $self->fqdn_to_ip4($fqdn, $resolver);
	push(@$result, @$subresult);
    }
    if (!defined($four_or_six) || ($four_or_six == IPV6_ONLY)) {
	my $subresult = $self->fqdn_to_ip6($fqdn, $resolver);
	push(@$result, @$subresult);
    }

    return $result;
}

sub fqdn_to_ip4 {
    my $self = shift;
    my $fqdn = shift;
    my $resolver = shift;

    my $result = [];

    $fqdn = $self->append_dot($fqdn);

    my $packet = $resolver->query($fqdn);
    if (defined($packet)) {
	my @answers = $packet->answer;
	foreach my $answer (@answers) {
	    if (uc($answer->type) eq 'A') {
		my $a = untaint_ip($answer->address);
		defined($a) && push(@$result, ($a));
	    }
	}
    }
    return $result;    
}

sub fqdn_to_ip6 {
    my $self = shift;
    my $fqdn = shift;
    my $resolver = shift;

    my $result = [];

    $fqdn = $self->append_dot($fqdn);

    my $packet = $resolver->query($fqdn, 'AAAA');
    if (defined($packet)) {
	my @answers = $packet->answer;
	foreach my $answer (@answers) {
	    if (uc($answer->type) eq 'AAAA') {
		my $a = untaint_ip($answer->address_short);
		defined($a) && push(@$result, ($a));
	    }
	}
    }
    return $result;
}

sub append_dot {
    my $self = shift;
    my $fqdn = shift;

    if (defined($fqdn)) {
	if ($fqdn =~ m,\.$,) {
	    return $fqdn;
	}
	return $fqdn . '.';
    }
    return undef;
}

=head2 lookup_nameservers(fqdn)

Look up the authoritive nameservers for the fully qualified domain name
B<fqdn>.  Returns an arrayref of IP addresses, or undef if there was
a problem performing the lookup.

=cut

sub lookup_nameservers {
    my $self = shift;
    my $fqdn = shift;
    my $recursing = shift;

    my $result = [];

    $fqdn = untaint_fqdn($fqdn);
    defined($fqdn) || die "fqdn is undefined";
    
    # we bootstrap by using the system's configured recursive nameservers
    my $resolver = Net::DNS::Resolver->new(recurse => 1,
					   dnssec => $self->use_dnssec,
					   debug => $self->debug_queries);

    my $packet = $resolver->send($fqdn, 'NS');
    if (!defined($packet)) {
	syslog(LOG_ERR, "no response was received for %s: are the "
	       . "system nameservers unavailable?", $fqdn);
	return undef;
    }

    my $rcode = $packet->header->rcode;
    if (uc($rcode) eq 'NOERROR') {

	# fqdn exists
	my @answers = $packet->answer;
	my @authorities = $packet->authority;
	if (scalar(@answers) > 0) {
	    foreach my $answer (@answers) {
		if (uc($answer->type) eq 'NS') {
		    my $ns = $answer->nsdname;
		    if (defined($ns)) {
			my $ips = $self->fqdn_to_ip($ns, $resolver);
			push(@$result, @$ips);
		    }
		}
	    }
	} elsif (scalar(@authorities) > 0) {
	    foreach my $auth (@authorities) {
		if (uc($auth->type) eq 'SOA') {
		    ($recursing) && die "infinite recursion?";
		    return $self->lookup_nameservers($auth->name);
		}
	    }
	}
    } elsif (uc($rcode) ne 'NXDOMAIN') {
	syslog(LOG_ERR, "unexpected rcode for %s: %s", $fqdn, $rcode);
    }

    my $untainted_result = [];
    foreach my $ip (@$result) {
	my $untainted_ip = untaint_ip($ip);
	push(@$untainted_result, ($untainted_ip)) if defined($untainted_ip);
    }
    
    return $untainted_result;
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

=head2 untaint_ip

This static method
takes a single argument that should be either an IPv4 or IPv6 address,
untaints it, and returns the untainted version. 
Returns undef if any checks fail or if the original valu ewas undef.

=cut

sub untaint_ip {
    my $value = shift;
    if (defined($value)) {
	if (($value =~ m,^([0-9\.]+)$,)
	    || ($value =~ m,^([a-f0-9]+:[:a-f0-9]+)$,i)) {
	    return $1;
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
	# we use fqdn_to_ip here because if the user passes in names
	# rather than IPs, we need to translate them to IPs so that the
	# resolvers don't get untainting errors down in their innards.
	if ($r eq '') {
	    if ($nameserver_arg ne '') {
		my $ips = $self->fqdn_to_ip($nameserver_arg);
		push(@$nameservers, @$ips);
	    }
	} elsif ($r = 'ARRAY') {
	    foreach my $na (@$nameserver_arg) {
		my $ips = $self->fqdn_to_ip($na);
		push(@$nameservers, @$ips);
	    }
	} else {
	    croak "the fourth argument to wait_for_challenge_propagation "
		. "must be a nameserver IP or an arrayref containing "
		. "nameserver IPs";
	}
	if (scalar(@$nameservers) < 1) {
	    croak "no nameservers were specified for $fqdn";
	}
    } else {
	$nameservers = $self->lookup_nameservers($fqdn);
	defined($nameservers) || return undef;

	if (scalar(@$nameservers) < 1) {
	    syslog(LOG_ERR, "no nameservers could be located for %s; "
		   . "does the FQDN exist?", $fqdn);
	    return undef;
	}
    }

    # set up the resolvers, one per nameserver
    my %resolvers_by_nameserver;
    foreach my $ns (@$nameservers) {
	my $resolver = Net::DNS::Resolver->new(nameservers => [$ns],
					       recurse => 0,
					       dnssec => $self->use_dnssec,
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
