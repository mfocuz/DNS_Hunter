#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';
$| = 1;

#use Devel::Camelcadedb;
use AnyEvent::DNS;
use JSON;
use Getopt::Long;

#########################
# PERL HELL BEGINS HERE #
#########################
my $DEBUG = 1;
my $DOMAIN;
my $MASK;
my $INITSUB_FILENAME;
my $LEET = 0;
my $OUTPUT_FILE;
my $UNIQ_THRESHOLD = 5;
my $MAX_DNS_QUERY_QUEUE = 10;
my $MAX_DNS_GENERATE;
my $NO_RESOLVE;
my $TAKEOVER;
my $HELP;
# Read options
GetOptions(
    "domain=s" => \$DOMAIN,
    "mask=s" => \$MASK,
    "sub-list=s" => \$INITSUB_FILENAME,
    "leet" => \$LEET,
    "output-file=s" => \$OUTPUT_FILE,
    "uniq=i" => \$UNIQ_THRESHOLD,
    "max-dns-query=i" => \$MAX_DNS_QUERY_QUEUE,
    "max-dns-gen=i" => \$MAX_DNS_GENERATE,
    "no-resolve" => \$NO_RESOLVE,
    "takeover" => \$TAKEOVER,
    "help" => \$HELP,
);

my %DICT_1337 = (
    111 => '0', 79  => '0',              # O,o
    108 => '1', 73  => '1', 105 => '1',  # l,I,i
    122 => '2', 90  => '2',              # Z,z
    101 => '3', 69  => '3',              # E,e
    97  => '4', 65  => '4',              # A,a
    115 => '5', 83  => '5',              # S,s
    98  => '6',                          # b
    116 => '7', 84  => '7',              # T,t
    66  => '8',                          # B
    103 => '9', 113 => '9',              # g,q
);

my %IP; # All resolved names
my @SUBDOMAINS; # Subdomain read from file
my @POSSIBLE_TAKEOVER; # CNAME domains found
my @TAKEOVERDOMAINS; # CNAME domains leads to unregistered domains!
# In theory, you can play with values of domain generation counter and domain resultion counter
# to find out best performance
$MAX_DNS_GENERATE = $MAX_DNS_QUERY_QUEUE * 10;

#######################
# CHECK INPUT OPTIONS #
#######################
if($HELP) {
    help();
    exit;
}
# Check if domain name is defined and contains of allowed characters
unless(defined $DOMAIN and $DOMAIN =~ /^([a-z0-9]|\-|\.)*$/) {
    print  "Error: Domain name should be set and can contains only a-z, 0-9 and '-'\n";
    print "Check --help\n";
    exit;
}
# Mask or domain list or both should be defined
unless (defined $MASK or defined $INITSUB_FILENAME) {
    print "Error: At least mask or domain list should be set\n";
    print "Check --help\n";
    exit;
}
# If mask defined, check its syntax
if (defined $MASK and $MASK !~ /^([a-z0-9]|{sub}|\-|\?d|\?c|\?a)*$/) {
    print "Error: Mask can contain only 'a-z', '0-9', '?d', '?c', '{sub}' and '-'\n";
    print "Check --help\n";
    exit;
}
# If mask and sublist defined, but mask do not contain {sub}
if (defined $MASK and defined $INITSUB_FILENAME and $MASK !~ /\{sub\}/) {
    print "Warning: You set --sub-list option but did not used it in mask, sublist will be skipped...\n";
    sleep 5; # Give 5 secodns to Ctrl+C
}

####################################
# Input parameters post processing #
####################################
if (defined $INITSUB_FILENAME and !defined $MASK) {
    $MASK = '{sub}';
}
# Read file with initial subdomain names
if (defined $INITSUB_FILENAME) {
    open(my $fhsd, '<', $INITSUB_FILENAME) or die "Error: Can not open domain-list file: $INITSUB_FILENAME\n";
    while(<$fhsd>) {
        chomp;
        next if ($_ eq "");
        push @SUBDOMAINS, $_;
    }
    close $fhsd;
    die "Error: Domain-list contains no words" if(scalar(@SUBDOMAINS) == 0);
}
# Check if output file exists and we can write there
if (defined $OUTPUT_FILE) {
    open(my $offh, '>', $OUTPUT_FILE) or die "Can not open output-file: $OUTPUT_FILE\n";
    open(my $offht, '>', $OUTPUT_FILE.".takeover") or die "Can not open output-file: $OUTPUT_FILE.takeover\n";
    close $offh;
    close $offht;
}

#############
# MAIN LOOP #
#############
# I. DNS hunting LOOP
print "\n\n===================\nStart Hunting...\n===================\n";
open(my $FH_DEBUG, '>', '/tmp/dns_hunter_last_names_to_resolve') or die "Can not open debug file for write"
    if ($DEBUG == 1);
my $dn_generator;
my $status_hunting = status($MASK);
# MASK + SUBDOMAIN
if (scalar(@SUBDOMAINS) > 0 && $MASK =~ /{sub}/) {
    $dn_generator = dn_gen_mask_n_sub($MASK,$status_hunting);
}
# ONLY MASK
elsif($MASK !~ /\{sub\}/) { # just in case
    $dn_generator = dn_gen_mask($MASK,$status_hunting);
}

while (my $domains = $dn_generator->())
{
    if($NO_RESOLVE) {
        print join("\n",@$domains);
        next;
    }

    bulk_resolve($domains);
}
close($FH_DEBUG)
    if ($DEBUG == 1);
print "\n\n===================\nHunting Completed!\n===================\n";

# II. DNS takeover LOOP
if (defined $TAKEOVER) {
    print "========Searching for possible subdomain takeover...========\n";
    open(my $FH_DEBUG_TO, '>', '/tmp/dns_hunter_last_names_to_takeover') or die "Can not open debug file for write"
        if ($DEBUG == 1);

    $possibleTakeOver = search_subdomain_takeover(\@POSSIBLE_TAKEOVER);
    if (scalar @$possibleTakeOver > 0 ) {
        print "Possible Domains Takeover Found!\nDomains:\n";
        print join("\n",@$possibleTakeOver),"\n===================";
        if (defined $OUTPUT_FILE) {
            open(my $fh, '>', $OUTPUT_FILE . ".takeover") or die "Can not open $OUTPUT_FILE.takeover for write";
            print $fh join("\n", @$possibleTakeOver);
        }
    }

    close $FH_DEGUB_TO if ($DEBUG == 1);
}
# III. Reporting
# 1. DNS huntining
print "Subdomains found:\n";
my $filterIP = {};
my $json = JSON->new;
foreach my $ip (keys %IP) {
    if ($IP{$ip}->{count} <= $UNIQ_THRESHOLD) {
        $filterIP->{$ip} = $IP{$ip};
    }
}
if(defined $OUTPUT_FILE) {
    open(my $fh1, '>', $OUTPUT_FILE) or print "Error: Can not open file $OUTPUT_FILE\n";
    print $fh1 $json->encode($filterIP);
    close $fh1;
}
print "\n",$json->encode($filterIP),"\n";

# 2. Domain Takeover
if (defined $TAKEOVER && scalar @TAKEOVERDOMAINS > 0 ) {
    if (defined $OUTPUT_FILE) {
        open(my $fh2, '>', $OUTPUT_FILE . ".takeover") or die "Can not open $OUTPUT_FILE.takeover for write";
        print $fh2 join("\n", @TAKEOVERDOMAINS);
        close $fh2;
    }
    print "Possible domains takeover found:\n";
    print join("\n",@TAKEOVERDOMAINS),"\n";
}


#############
# FUNCTIONS #
#############
sub dn_gen_mask_n_sub {
    my ($mask, $status) = @_;

    my @_TOKENS;
    my @iStr = split('',$mask);
    # Tokenize input stream(mask)
    for(my $t=0,my $_token=''; $t<=$#iStr;) {
        if($iStr[$t] eq '{') {
            push @_TOKENS,$_token if ($_token ne '');
            $_token = "";
            if ($iStr[$t + 1] eq 's' &&
                $iStr[$t + 2] eq 'u' &&
                $iStr[$t + 3] eq 'b' &&
                $iStr[$t + 4] eq '}'
            ) {
                push @_TOKENS, join('',
                    $iStr[$t],
                    $iStr[$t + 1],
                    $iStr[$t + 2],
                    $iStr[$t + 3],
                    $iStr[$t + 4]);
                $t += 5;
            } else {
                die "Error: Died while mask parsing, check syntax.\n";
            }
        } elsif($t == $#iStr) {
            $_token .= $iStr[$t];
            push @_TOKENS,$_token;
            $t++;
        } else {
            $_token .= $iStr[$t];
            $t++;
        }

    }

    # Build initial state
    my @_GEN_STATE = (0) x scalar(@_TOKENS);
    my @_STATE_SWITCH_COND = (1) x (scalar(@_TOKENS) - 1);
    my $round = 0;
    my $last = 0;
    # Build STATE SWITCH modulus numbers
    for(my $r=$#_GEN_STATE-1; $r >=0; $r--) {
        my $token = $_TOKENS[$r+1];
        my $power;
        if ($token eq '{sub}') {
            $power = scalar(@SUBDOMAINS);
        } else {
            $power = 1;
        }
        if ($r == $#_GEN_STATE-1) {
            $_STATE_SWITCH_COND[$r] = $power;
        } else {
            $_STATE_SWITCH_COND[$r] = $power * $_STATE_SWITCH_COND[$r+1];
        }
    }
    # Calc maximum (to detect when completed)
    my $firstTokenMax = ($_TOKENS[0] eq '{sub}') ? scalar(@SUBDOMAINS) : 1;
    my $max = (scalar(@_STATE_SWITCH_COND) > 0) ? $_STATE_SWITCH_COND[0] * $firstTokenMax : $firstTokenMax;

    my $next_state = sub {
        $round++;
        return undef if ($round == $max);
        for (my $i = 0; $i<=$#_GEN_STATE ; $i++) {
            my $modulus = ($_TOKENS[$i] eq '{sub}') ? scalar(@SUBDOMAINS) : 1;
            if ($i == $#_GEN_STATE ) {
                $_GEN_STATE[$i] = ($_GEN_STATE[$i] + 1) % $modulus;
            }
            elsif ($round % $_STATE_SWITCH_COND[$i] == 0) {
                $_GEN_STATE[$i] = ($_GEN_STATE[$i] + 1) % $modulus;
            }
        }
    };

    my $compile_mask = sub {
        my $_mask = "";
        for (my $i = 0; $i<=$#_GEN_STATE ; $i++) {
            if($_TOKENS[$i] eq '{sub}') {
                $_mask .= @SUBDOMAINS[$_GEN_STATE[$i]];
            } else {
                $_mask .= $_TOKENS[$i];
            }
        }
        return $_mask;
    };

    # Initialize zero generator
    my $gen_by_mask_n_sub = generate_by_mask($compile_mask->());

    my $generator = sub {
        return undef if (1 == $last);
        my @words;
        my $completed = 0;
        for (my $i = 0; $i < $MAX_DNS_GENERATE;) {
            my $generated = $gen_by_mask_n_sub->();
            unless (defined $generated) {
                if (defined $next_state->()) {
                    $gen_by_mask_n_sub = generate_by_mask($compile_mask->());
                    next;
                } else {
                    $last = 1;
                    last;
                }
            }
            push @words, $generated;
            $i++;
            if($LEET) {
                my @leetSub = keys %{generate_1337_speak($generated)};
                push @words,@leetSub;
                $i += scalar(@leetSub);
            }
            $completed = ($i > $MAX_DNS_GENERATE) ? $MAX_DNS_GENERATE : $i;
        }
        $status->($completed,$words[$#words]);
        return \@words;
    };
    return $generator;
}

sub dn_gen_mask {
    my ($mask, $status) = @_;

    my $last = 0;
    my $gen_by_mask = generate_by_mask($mask);
    my $generator = sub {
        return undef if ($last == 1);
        my @words;
        for (my $i = 0; $i < $MAX_DNS_GENERATE;) {
            my $generated = $gen_by_mask->();
            unless (defined $generated) {
                $last = 1;
                last;
            }
            push @words, $generated;
            $i++;
        }
        $status->(scalar(@words),$words[$#words]);
        return \@words;
    };
    return $generator;
}

sub bulk_resolve {
    my $domains = shift;

    my $resolver = AnyEvent::DNS::resolver;
    $resolver->max_outstanding($MAX_DNS_QUERY_QUEUE);
    my @condvars;

    if ($DEBUG == 1) {
        print $FH_DEGUB join("\n",@$domains);
    }

    foreach my $domain (@$domains) {
        $resolver->resolve($domain . '.' . $DOMAIN, "*", my $condvar  = AnyEvent->condvar);
        push @condvars, $condvar;
    }

    while (my $condvar = pop @condvars) {
        my $resolved = $condvar->recv;
        next until ref($resolved) eq 'ARRAY';
        my ($domain, $entryType, $hz1, $hz2, $ip) = @$resolved;
        if ($entryType eq "cname") {
            push @POSSIBLE_TAKEOVER,$ip;
        }
        my $dnsEntry = {$entryType => $domain};
        if (!defined $IP{$ip}) {
            $IP{$ip} = {
                domains => [$dnsEntry],
                count => 1,
            };
        } elsif($IP{$ip}->{count} >= $UNIQ_THRESHOLD) {
            $IP{$ip}->{count} += 1;
        }
        else {
            push @{$IP{$ip}->{domains}},$dnsEntry;
            $IP{$ip}->{count} += 1;
        }
    }
}

sub search_subdomain_takeover {
    my $domains = shift;

    my @condvars;
    my %loopChecker;
    my %nameChains; # hash of arrays
    my @possibleTakeover;

    if ($DEBUG == 1) {
        print $FH_DEGUB_TO join("\n",@$domains);
    }

    my $resolver = AnyEvent::DNS::resolver;
    $resolver->max_outstanding($MAX_DNS_QUERY_QUEUE);

    # Fill initial name chains
    foreach (@$domains) {
        $nameChains{$_} = [$_];
    }

    my $resolver_func = sub {
        my $domain = shift;
        $resolver->resolve($domain, "*", my $condvar  = AnyEvent->condvar);
        push @condvars, [$domain,$condvar];
    };

    my $chain_searcher = sub {
        my $previousName = shift;
        my $newName = shift;

        foreach my $firstUnit (keys %nameChains) {
            my $isMatched = grep {$_ eq $previousName} @{$nameChains{$firstUnit}};
            if ($isMatched != 0) {
                push @{$nameChains{$firstUnit}},$newName;
                last;
            }
        }
    };

    foreach my $d (@$domains) {
        $resolver_func->($d);
    }

    while (my $condvar = pop @condvars) {
        my ($d,$resolved) = ($condvar->[0],$condvar->[1]->recv);
        # For resolved names, check if its also cname in case its cname chain, we need to find final
        if (ref($resolved) eq 'ARRAY') {
            my ($domain, $entryType, $hz1, $hz2, $ip) = @$resolved;

            if ($entryType eq 'cname' && !defined $loopChecker{$ip}) {
                # mark name as checked to identify loop
                $loopChecker{$d} = 1;
                # Add CNAME to chain
                $chain_searcher->($domain,$ip);
                # resolve new cname
                $resolver_func->($ip);
            }
        } else {
            push @possibleTakeover,$d;
        }
    }

    return \@possibleTakeover;
}

# 1337 generator
# Input:    1) word
#           2) leet alphabet in format { $ascii_code => $char(e.g. "3" }
# Output:   Hash with leet words in format {$leet_word => '1'}
sub generate_1337_speak {
    my $word = shift;
    my $dict1337 = \%DICT_1337;

    my %words1337;
    my $speak1337;
    $speak1337 = sub {
        my $string = shift;
        my $pos = shift;

        my @string = split //,$string;
        if ($pos == (length($string))) {
            return;
        }

        my $leetChar = $dict1337->{ord($string[$pos])};
        if(defined $leetChar) {
            # w/o leet
            $speak1337->($string,$pos+1);
            # w/ leet
            $string[$pos] = $leetChar;
            my $leetString = join('',@string);
            $words1337{$leetString} = 1;
            $speak1337->($leetString,$pos+1);
        } else {
            # call itself with next position
            $speak1337->($string,$pos+1);
        }
    };

    $speak1337->($word,0);
    return \%words1337;
}

#
# Input:
# Output:
sub generate_by_mask {
    my $mask = shift;

    my @inputStream = grep {$_ ne ""} split('',$mask);
    my @_TOKENS;

    # Break input stream into tokens
    for(my $t=0; $t<=$#inputStream;) {
        if($inputStream[$t] eq '?') {
            my $token = $inputStream[$t] . $inputStream[$t+1];
            push @_TOKENS,$token;
            $t +=2;
        } else {
            my $token = $inputStream[$t];
            push @_TOKENS,$token;
            $t++;
        }
    }

    # build initial state
    my @_GENSTATE = (0) x scalar(@_TOKENS);
    my $last = 0;

    my @chars = split('',"abcdefghijklmnopqrstuvwxyz");
    #my @chars = split('',"abc"); # for testing
    my @digits = split('',"0123456789");
    #my @digits = split('',"01"); # for testing
    my @both;
    push @both,@chars,@digits;

    my %_TYPES = (
        '?c' => \@chars,
        '?d' => \@digits,
        '?a' => \@both,
    );

    # Build STATE SWITCH modulus numbers
    my $round = 0;
    my @_STATE_SWITCH_MOD;
    for (my $r = $#_GENSTATE-1; $r>=0; $r--) {
        my $token = $_TOKENS[$r+1];
        my $power;
        if (defined $_TYPES{$token}) {
            $power = scalar(@{$_TYPES{$token}});
        } else {
            $power = 1;
        }
        if ($r == $#_GENSTATE-1) {
            $_STATE_SWITCH_MOD[$r] = $power;
        } else {
            $_STATE_SWITCH_MOD[$r] = $power * $_STATE_SWITCH_MOD[$r+1];
        }
    }
    # Calc maximum (to detect when completed)
    my $firstTokenMax = (defined $_TYPES{$_TOKENS[0]}) ?  scalar(@{$_TYPES{$_TOKENS[0]}}) : 1;
    my $max = (scalar(@_STATE_SWITCH_MOD)>0) ? $_STATE_SWITCH_MOD[0] * $firstTokenMax : $firstTokenMax;

    my $next_state = sub {
        $round++;
        return undef if ($round == $max+1);
        for (my $i = 0; $i<=$#_GENSTATE ; $i++) {
            my $modulus = (defined $_TYPES{$_TOKENS[$i]}) ? scalar(@{$_TYPES{$_TOKENS[$i]}}) : 1;
            if ($i == $#_GENSTATE ) {
                $_GENSTATE[$i] = ($_GENSTATE[$i] + 1) % $modulus;
            }
            elsif ($round % $_STATE_SWITCH_MOD[$i] == 0) {
                $_GENSTATE[$i] = ($_GENSTATE[$i] + 1) % $modulus;
            }
        }
    };

    my $generate_char = sub {
        my $pos = shift;

        my $token = $_TOKENS[$pos];
        my $char;
        if ($token =~ /\?\w/) {
            my $index = $_GENSTATE[$pos];
            $char = $_TYPES{$token}->[$index];
        } else {
            $char = $token
        }

        return $char;
    };

    my $generator = sub {
        my $word = "";
        return undef if ($last == 1);
        for (my $i = 0; $i<= $#_GENSTATE; $i++) {
            $word .= $generate_char->($i);
        }
        (defined $next_state->()) ? return $word : return undef;
    };

    return $generator;
}

sub status {
    my $mask = shift;

    my @_TOKENS_VALUES;
    my @iStr = split('',$mask);
    # Tokenize input stream(mask)
    for(my $t=0,my $_token=''; $t<=$#iStr;) {
        if($iStr[$t] eq '{') {
            $_token = "";
            if ($iStr[$t + 1] eq 's' &&
                $iStr[$t + 2] eq 'u' &&
                $iStr[$t + 3] eq 'b' &&
                $iStr[$t + 4] eq '}'
            ) {
                push @_TOKENS_VALUES, scalar(@SUBDOMAINS);
                $t += 5;
            } else {
                die "Error: Died while mask parsing, check syntax.\n";
            }
        } elsif($iStr[$t] eq '?') {
            if ($iStr[$t+1] eq 'c') {
                push @_TOKENS_VALUES,26;
            } elsif($iStr[$t+1] eq 'd') {
                push @_TOKENS_VALUES,10;
            } elsif($iStr[$t+1] eq 'a') {
                push @_TOKENS_VALUES,36;
            }
            $t+=2;
        } else {
            push @_TOKENS_VALUES,1;
            $t++;
        }

    }

    my $totalRequests = 1;
    foreach (@_TOKENS_VALUES) {
        $totalRequests *= $_;
    }
    my $totalCompleted = 0;

    my $generator = sub {
        my $completed = shift;
        my $lastResolved = shift;
        $totalCompleted += $completed;
        print "\r"," " x 100;
        print "\rProgress: " . sprintf("%.2f",($totalCompleted/$totalRequests) * 100) . '%' . "\t\tLast name checked: $lastResolved";
    };

    return $generator;
}

sub help {
    print "\nRequired options:\n";
    print "\t--domain <domain name>                - domain address to brute.\n";
    print "\t--output-file </path/to/file>         - file to save results\n";
    print "\nOne of the following bruting option required(or both can be used):\n";
    print "\t--mask <mask>                         - mask for bruting\n";
    print "\t--sub-list </path/to/subdomain/list>  - subdomain list\n";
    print "\nOptional parameters:\n";
    print "\t--uniq <number> (default:5)           - Uniq IP address threshold\n";
    print "\t--max-dns-query <number> (default:10) - Number of parallel DNS resolutions.\n";
    #print "\t--max-dns-gen <number>\tNumber of domains to generate before resolution\n";
    print "\t--no-resolve                          - Only generates domain names w/o resolving\n";
    print "\t--leet                                - Replace chars with 1337 numbers!\n";
    print "\nMask syntax:\n";
    print "\t?c - char\n\t?d - digit\n\t?a - digit+char\n\t{sub} - subdomain\n\tAny bare chars can be used as is.\n";
    print "\nExample: ./dns_hunter --domain example.com --output-file /tmp/result --sub-list /tmp/sub.list\n";
    print "\t\t--mask '?c?c-{sub}-?d?d-{sub}-anywords'\n";
    print "\n";
}
