package Net::ACMEClient::DNS::ZoneEditor;

use warnings;
use strict;
use Carp;
use File::Copy;

=head1 NAME

Net::ACMEClient::DNS::ZoneEditor - limited zone file editor

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

This module is used to write DNS challenges including updating the 
appropriate SOA serial number.  It is intended as a helper to be used
indirectly through the B<acme-client>(1) program.  A common deployment
would see this module installed on the machine that is running the 
nameserver (which is not necessarily the same as the one that is running
B<acme-client>).

    use Net::ACMEClient::DNS::ZoneEditor;

    my $foo = Net::ACMEClient::DNS::ZoneEditor->new(
              base_name => '/path/to/zones/master/example.com.zone');
    $foo->write_challenge('www.example.com', $challenge_string, 'www');
    $foo->increment_soa;

For safety it assumes that the challenge and SOA
records are in files by themselves (ie: no other records) and that the
files would be $INCLUDEd by the appropriate zone files.  It is the user's
responsibility to ensure that these files are set up appropriately during
the initial provisioning (ie: before this module is run for the first time).

=head1 ATTRIBUTES

The following attributes may be provided to the new method:

=head2 base_name

This is the base name of the files to write when using 
B<write_challenge> and B<increment_soa>.

=head2 challenge_suffix

When the B<write_challenge> method is invoked, the challenge file name
is constructed by appending B<base_name>, B<challenge_suffix>, and
the suffix argument of the B<write_challenge> method.

By default, B<challenge_suffix> is B<-chal->.

=head2 challenge_ttl

This is the TTL value to use for the challenge record.  By default it is
B<1> (second).  Do not use zero as this may cause a problem with some
nameserver implementations.

=head2 new_file_suffix

When writing files, a temporary file will first be written and then
renamed to the final file name.  The name of the temporary file is 
based on the final file name, and has B<new_file_suffix> appended to the end.
The default value is B<-new>.

=head2 soa_suffix

This suffix is appended to B<base_name> to derive the filename to write
when the B<increment_soa> method is invoked.  By default it is B<-soa>.

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
for my $field(qw(base_name challenge_suffix challenge_ttl
                 new_file_suffix prog_name soa_suffix)) {
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
    $self->challenge_suffix('-chal-');
    $self->challenge_ttl(1);
    $self->new_file_suffix('-new');
    $self->soa_suffix('-soa');
    
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
    my $ttl = $self->challenge_ttl;
    if ($ttl < 1) {
	# a TTL of zero can cause problems with some nameserver
	# implementations.
	$self->challenge_ttl(1);
    }

    # set private members
}

sub increment_soa {
    my $self = shift;
}

=head2 write_challenge(fqdn, challenge, suffix)

Write a DNS challenge file, where the filename is constructed as described
in the B<challenge_suffix) description, above.  The file must already exist,
and should either be empty or only contain old challenges; it's contents
will be replaced with the new challenge.

=cut
    
sub write_challenge {
    my $self = shift;
    my $fqdn = shift;
    my $challenge = shift;
    my $suffix = shift;

    my $base_name = $self->base_name;
    my $challenge_suffix = $self->challenge_suffix;
    my $new_file_suffix = $self->new_file_suffix;
    my $ttl = $self->challenge_ttl;

    defined($base_name) || croak "base_name was not defined";
    defined($challenge_suffix) || croak "challenge_suffix was not defined";
    defined($new_file_suffix) || croak "new_file_suffix was not defined";
    defined($ttl) || croak "challenge_ttl was not defined";

    defined($fqdn) || croak "fqdn was not defined";
    defined($challenge) || croak "challenge was not defined";
    defined($suffix) || croak "suffix was not defined";

    # validate and untaint
    if ($base_name =~ m,^([-_a-z0-9\./]+)$,i) {
	$base_name = $1;
    }

    if ($challenge_suffix =~ m,^([-_\.a-z0-9]+)$,i) {
	$challenge_suffix = $1;
    } else {
	croak "illegal characters in challenge_suffix";
    }

    if ($new_file_suffix =~ m,^([-_\.a-z0-9]+)$,i) {
	$new_file_suffix = $1;
    } else {
	croak "illegal characters in new_file_suffix";
    }

    if ($ttl =~ m,^(\d+[smhdw]?)$,) {
	$ttl = $1;
    } else {
	croak "illegal characters in challenge_ttl";
    }

    if ($fqdn =~ m,^([a-z0-9]+[-\.a-z0-9]+)$,i) {
	$fqdn = $1;
    } else {
	croak "illegal characters in fqdn";
    }

    if ($challenge =~ m,^([-_a-z0-9]+\.[-_a-z0-9]+)$,i) {
	$challenge = $1;
    } else {
	croak "illegal characters in challenge (or malformed challenge)";
    }

    if ($suffix =~ m,^([-_\.a-z0-9]+)$,i) {
	$suffix = $1;
    } else {
	croak "illegal characters in suffix provided to "
	    . "write_challenge method";
    }


    my $challenge_file = $base_name . $challenge_suffix . $suffix;
    if (! -f $challenge_file ) {
	croak "challenge file $challenge_file does not exist; it should "
	    . "have been created prior to running this program";
    }

    my $new_file = $challenge_file . $suffix;
    open(my $fh, ">", $new_file)
	|| croak "can't open $new_file for writing: $!";
    printf($fh "_acme-challenge.%s.\t%s\tIN\tTXT\t\"%s\"\n",
	   $fqdn, $ttl, $challenge);
    close($fh) || croak "failed to close $new_file: $!";
    move($new_file, $challenge_file)
	|| croak "failed to rename $new_file to $challenge_file: $!";

    1;
}

=head1 SEE ALSO

B<acme-client>(1)

=head1 AUTHOR

Devin Reade, C<< <gdr at gno.org> >>

=head1 BUGS

B<increment_soa> assumes that there is only one SOA record in the file.
Consequently, only the first such record will have its serial number
incremented.

B<increment_soa> treats the serial as strictly numeric.  If your SOA
is using the encoded date convention, do not expect the new serial number
to, in general, match the current date.

Please report any bugs or feature requests to C<bug-net-acmeclient-dns-zoneeditor at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-ACMEClient-DNS-ZoneEditor>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::ACMEClient::DNS::ZoneEditor


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-ACMEClient-DNS-ZoneEditor>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Net-ACMEClient-DNS-ZoneEditor>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Net-ACMEClient-DNS-ZoneEditor>

=item * Search CPAN

L<http://search.cpan.org/dist/Net-ACMEClient-DNS-ZoneEditor/>

=back


=head1 LICENSE AND COPYRIGHT

Copyright 2017 Devin Reade.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of Net::ACMEClient::DNS::ZoneEditor
