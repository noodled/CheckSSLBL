use strict;
use warnings;
use Text::CSV;
use Time::HiRes;
use Crypt::OpenSSL::X509;

use v5.14;

my $start = Time::HiRes::gettimeofday();

my %bad_thumbprints;
my $csv = Text::CSV->new( { sep_char => ',' } );

my $file = 'sslblacklist.csv';

open( my $data, '<', $file ) or die "Could not open '$file' $!\n";
while ( my $line = <$data> ) {
    chomp $line;

    if ( $csv->parse($line) ) {

        my @fields = $csv->fields();

        if ( $fields[1] ) {
            $bad_thumbprints{ $fields[1] } = $fields[2];
        }
    }
    else {
        warn "Line could not be parsed: $line\n";
    }
}

my $cert_count = 0;
my $certificate_string;
my $source_ip;
my $dest_ip;
my $connection_no;
my $IP_ADDR = qr/\d+\.\d+\.\d+\.\d+/;
my $c       = 0;

while (<>) {
    chomp;

    for ($_) {

        when (
m/New TCP connection #(\d+): ($IP_ADDR)\(\d+\) <-> ($IP_ADDR)\(\d+\)/
          )
        {

            $connection_no = $1;
            $source_ip     = $2;
            $dest_ip       = $3;
        }
        when (m/^\s+Certificate\s*$/) {
            $c = 1;
        }
        when (m/^\S+/) {
            $c = 0;
        }
    }

    if ( $c == 1 ) {
        $certificate_string = $certificate_string . $_;
    }
    elsif ( $c == 0 && $certificate_string ) {
        $certificate_string =~ s/\n//g;
        $certificate_string =~ s/ //g;
        my @certificates =
          split( /certificate\[\d+\]=/, $certificate_string );
        $cert_count += scalar @certificates;
        foreach my $certificate (@certificates) {
            if ( $certificate ne 'Certificate' ) {
                my $der_encoded_data = pack "H*", $certificate;
                my $x509 =
                  Crypt::OpenSSL::X509->new_from_string( $der_encoded_data,
                    Crypt::OpenSSL::X509::FORMAT_ASN1 );
                my $thumbprint = $x509->fingerprint_sha1();
                $thumbprint = lc $thumbprint;
                $thumbprint =~ s/://g;
                if ( exists( $bad_thumbprints{$thumbprint} ) ) {
                    print
"ALERT: Bad Thumbprint ($thumbprint) detected indicating $bad_thumbprints{$thumbprint} malware. Source IP: $source_ip Dest IP: $dest_ip \n";
                }
            }
        }
        undef $certificate_string;
    }
}

my $end      = Time::HiRes::gettimeofday();
my $run_time = $end - $start;
print "Processed $cert_count certificates in $run_time \n";
