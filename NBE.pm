
package Parse::Nessus::NBE;

use strict;
use vars qw/ $VERSION @ISA @EXPORT_OK /;

require Exporter;

@ISA = qw/ Exporter /;
@EXPORT_OK = qw/ nbanners nports nplugin nwebdirs nnfs nos nsnmp/;

$VERSION = '.01';

use constant WEBDIR => 11032; # nessus plugin id for web directories discovered
use constant NFS => 10437; 	# nessus plugin id for nfs shares discovered
use constant NMAP1 => 10336;  # nessus plugin id for Nmap OS guess
use constant NMAP2 => 11268;  # nessus plugin id for Nmap OS guess
use constant QUESO => 10337;  # nessus plugin id for QueSO OS guess

sub nbanners {
  my (@ndata) = @_;
  my (@banners);
  foreach my $nbanner (@ndata) {
  if ($nbanner =~ /emote(.*)server (banner|type)/)  {
  my @result = split (/\|/, $nbanner);
	$result[6] =~ s/^(.*)\:\\n|Solution (.*)$|\\r|\\n//g;
	push @banners , join "|" , $result[2] , $result[6];
  }

}
	return @banners;
}

sub nports {
my (@ndata) = @_;
my (@ports);
my $nport = pop(@ndata);
foreach my $ndata (@ndata) {
my @result = split (/\|/, $ndata);
if ($result[4]) {
next;
}
elsif ($result[3] =~ /\($nport\//) {
push @ports , join "|" , $result[2] , $result[3];
}
}
return @ports;
}

sub nplugin {
my (@ndata) = @_;
my (@plugins);
my $nplugin = pop(@ndata);
foreach my $ndata (@ndata) {
my @result = split (/\|/, $ndata);
if (! $result[4]) {
next;
}
elsif ($result[4] =~ /$nplugin/) {
$result[6] =~ s/\\n//;
push @plugins, join "|" , $result[2] , $result[3] , $result[6];
}
}
return @plugins;
}

sub nwebdirs {
my (@ndata) = @_;
my (@webdirs);
my $webdirplugin = WEBDIR;
foreach my $ndata (@ndata) {
my @result = split (/\|/, $ndata);
if (! $result[4]) {
next;
}
elsif ($result[4] =~ /$webdirplugin/) {
$result[6] =~ s/(^(.*)discovered\:|\\n|,)//g;
$result[6] =~ s/The following(.*)authentication:/\|/;
push @webdirs, join "|" , $result[2] , $result[3] , $result[6];
}
}
return @webdirs;
}

sub nnfs {
my (@ndata) = @_;
my (@nfs);
my $nfsplugin = NFS;
foreach my $ndata (@ndata) {
my @result = split (/\|/, $ndata);
if (! $result[4]) {
next;
}
elsif ($result[4] =~ /$nfsplugin/) {
$result[6] =~ s/^(.*) \: \\n|\\n\\n(.*)$//g;
$result[6] =~ s/\\n/,/g;
push @nfs, join "|" , $result[2] , $result[3] , $result[6];
}
}
return @nfs;
}

sub nos {
my (@ndata) = @_;
my (@os);
foreach my $ndata (@ndata) {
if ($ndata =~ m/10336\|Security Note|11268\|Security Note|10337\|Security Note/) {
my @result = split (/\|/, $ndata);
	if ($result[4] eq NMAP1) {
	$result[6] =~ s/(Nmap(.*)running |(\;|\\n))//g;
	push @os , join "|" ,  $result[2] , $result[6];
	}
	elsif ($result[4] eq NMAP2) {
	$result[6] =~ s/(Remote OS guess : |\\n\\n(.*)$)//g;
	push @os , join "|" ,  $result[2] , $result[6];
	}
	elsif ($result[4] eq QUESO) {
	$result[6] =~ s/(QueSO has(.*)\\n\*|\\n\\n\\nCVE (.*)$| \(by (.*)$)//g;
	push @os , join "|" ,  $result[2] , $result[6];
	}
}
}
return @os;
}

sub nsnmp {
my (@ndata) = @_;
my (@snmp);
foreach my $ndata (@ndata) {
if ($ndata =~ m/10264\|Security Hole\|/) {
my @result = split (/\|/, $ndata);
        $result[6] =~ s/\\nSNMP Agent(.*?)community name: //;
        $result[6] =~ s/(\\nSNMP Agent (.*?)community name: |\\nCVE(.*)$)/ /g;
        push @snmp, join "|" , $result[2] , $result[6];
        }
}
return @snmp;
}

1;

__END__

=pod

=head1 NAME

Parse::NessusNBE - use to extract specific data from nessus nbe files

=head1 SYNOPSIS

	use Text::NessusNBE;

	function(@nessusdata);
	
	function(@nessusdata,$query);	

=head1 DESCRIPTION

This module is designed to extract information from nessus nbe files. Certain functions have been designed to return certain sets of data, such as service banners and OS versions. Other functions have been provided that will return more specific information, such as all IPs listening on a given port or all IPs associated with a specified plugin id.

=head1 EXAMPLES

To obtain a list of banners

	my @banners =  nbanners(@nessusdata);
	print @banners;
	
	# returns 
	IP|service banner
	...

To query by port

	my $port = 80;
	my @ports = nports(@nessusdata,$port);		
	print @ports;
	
	# returns 
	IP|specified port
	...

To obtain a list of web directories

	my @webdirs = nwebdirs(@nessusdata);		
	print @webdirs;
	
	# returns 
	IP|web port|web dir(s)|web dir(s) requiring authentication
	...

To obtain a list of nfs shares

	my @nfs = nnfs(@nessusdata);				
	print @nfs;
	
	# returns 
	IP|nfs port|nfs share(s)
	...

To obtain a OS listing

	my @os = nos(@nessusdata);				
	print @os;
	
	# returns 
	IP|OS version
	...

To obtain a listing of SNMP community strings

	my @snmp = nsnmp(@nessusdata);				
	print @snmp;

	# returns 
	IP|SNMP community string(s)
	...

To query by plugin id

	my $plugin = 10667;
	my @plugin = nplugin(@nessusdata,$plugin); 	
	print @plugin;

	# returns
	IP|port|plugin data
	...

=head1 AUTHOR

David J Kyger, dave@norootsquash.net

=head1 COPYRIGHT

Copyright 2003 David J Kyger. All rights reserved.

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut

