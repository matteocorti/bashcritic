#!/usr/bin/perl

## To do
## * lines too long
## * variables w/o {}
## * are the parentheses needed/suggested in the function definition?
#
## http://www.bash-hackers.org/wiki/doku.php?id=scripting:obsolete
## http://www.bash-hackers.org/wiki/doku.php?id=scripting:nonportable

use 5.008;
use strict;
use warnings;
use Carp;

eval 'exec /usr/bin/perl  -S $0 ${1+"$@"}'
    if 0; # not running under some shell

use version; our $VERSION = '1.0.0';

use Data::Dumper;
use File::Slurp;
use English qw(-no_match_vars);
use Getopt::Long;
use Pod::Usage qw(pod2usage);
use List::Util qw(first);

##############################################################################
# Configuration

Getopt::Long::Configure( 'bundling', 'ignorecase', );

##############################################################################
# Global vars

my @checks;

my $help;
my $verbosity = 0;

# constants

my $GENTLE = 5;
my $STERN  = 4;
my $HARSH  = 3;
my $CRUEL  = 2;
my $BRUTAL = 1;

my $NAME_PATTERN = '[A-Za-z0-9_]+';

##############################################################################
# Subroutines

##############################################################################
# Usage     : verbose("some message string", $optional_verbosity_level);
# Purpose   : write a message if the verbosity level is high enough
# Returns   : n/a
# Arguments : message : message string
#             level   : options verbosity level
# Throws    : n/a
# Comments  : n/a
# See also  : n/a
sub verbose {

    # arguments
    my $message = shift;
    my $level   = shift;

    if ( !defined $level ) {
        $level = 0;
    }

    if ( $level < $verbosity ) {
        print $message;
    }

    return;

}

sub perform_checks {

    my $file = shift;

    for my $check (@checks) {
        &$check($file, read_file($file));
    }
    
    return;

}

# check templates

sub check_pattern {
    
    my $file    = shift;
    my $pattern = shift;
    my $message = shift;
    my @lines   = @_;
    
    my $counter = 0;

    for my $line (@lines) {
        $counter++;
        if ($line =~ /$pattern/mx) {
            my $error = $message;
            $error =~ s/LINE_NUMBER/$counter/mx;
            print "$error\n";
        }
    }

    return;
    
}

##############################################################################
# Main

############################
# Parse command line options

Getopt::Long::Configure(
    'bundling',
    'no_ignore_case'
);

my $result = GetOptions(
    'help|h|?'          => \$help,
    'verbose|v+'        => \$verbosity,
    'version|V'         => sub { print "bashcritic version $VERSION\n"; exit; }
);

##############################
# Parse command line arguments

my @FILES = ();

if ( !@ARGV || (@ARGV == 1 && $ARGV[0] eq q{-}) )  {

    # Reading code from STDIN.  All the code is slurped into
    # a string.  PPI will barf if the string is just whitespace.
    my $code_string = do { local $RS = undef; <STDIN> };

    # Notice if STDIN was closed (pipe error, etc)
    if ( ! defined $code_string ) {
        $code_string = q{};
    }

    $code_string =~ m{ \S+ }mx || confess qq{Nothing to critique.\n};
    @FILES = \$code_string;    #Convert to SCALAR ref for PPI
}
else {

    # Test to make sure all the specified files or directories
    # actually exist.  If any one of them is bogus, then die.
    if ( my $nonexistant = first { ! -e $_ } @ARGV ) {
        my $msg = qq{No such file or directory: '$nonexistant'};
        pod2usage( -exitstatus => 1, -message => $msg, -verbose => 0);
    }
    
    @FILES = @ARGV;
}

@checks = (

    ####################
    # portability checks
    #
    # checks from rules described by http://www.bash-hackers.org/wiki/doku.php?id=scripting:nonportable

    # source FILE
    sub {
        my $file = shift;
        check_pattern(
            $file,
            'source\ ',
            "Severity $STERN at $file:LINE_NUMBER: "
                . '"source FILE" is not portable use ". FILE" instead',
            @_,
        );
    },

    # declare keyword
    sub {
        my $file = shift;
        check_pattern(
            $file,
            'declare\ ',
            "Severity $STERN at $file:LINE_NUMBER: "
                . '"declare keyword" is not portable use "typeset keyword" to define local variables '
                    . '(or variables with special attributes)',
            @_,
        );
    },

    # here strings
    sub {
        my $file = shift;
        check_pattern(
            $file,
            '<<<',
            "Severity $STERN at $file:LINE_NUMBER: "
                . 'Avoid here-strings (a special form of the here-document) in portable scripts',
            @_,
        );
    },

    # export with assignment
    sub {
        my $file = shift;
        check_pattern(
            $file,
            'export\ .*=',
            "Severity $STERN at $file:LINE_NUMBER: "
                . 'Though POSIX allows it, many shells don’t want the assignment and the exporting in one command',
            @_,
        );
    },

    # arithmetic compunds
    sub {
        my $file = shift;
        check_pattern(
            $file,
            '^[^:]*\(\(.*\)\)',
            "Severity $STERN at $file:LINE_NUMBER: "
                . 'POSIX does’t define an arithmetic compund command, many shells don’t know it. Using the pseudo-command : and the arithmetic expansion $(( )) is a kind of workaround here.',
            @_,
        );
    },

    # Bashish test keyword 
    sub {
        my $file = shift;
        check_pattern(
            $file,
            '\[\[\ .*\ \]\]',
            "Severity $STERN at $file:LINE_NUMBER: "
                . 'The Bashish test keyword "[[" is reserved by POSIX®, but not defined. Use the old fashioned way with the test command ("test" or "[").',
            @_,
        );
    },

    #####################
    # obsolete constructs
    #
    # http://www.bash-hackers.org/wiki/doku.php?id=scripting:obsolete

    # c-shell redirection
    sub {
        my $file = shift;
        check_pattern(
            $file,
            '(&>)|(>&)',
            "Severity $STERN at $file:LINE_NUMBER: "
                . 'The &>FILE >&FILE redirection syntax is short for >FILE 2>&1 and is derived from the C-Shell. It’s very old and not part of POSIX',
            @_,
        );
    },

    # $[ EXPRESSION ]
    sub {
        my $file = shift;
        check_pattern(
            $file,
            '\$\[.*\]',
            "Severity $STERN at $file:LINE_NUMBER: "
                . 'The $[EXPRESSION] syntax is completely replaced by the POSIX-conform arithmetic expansion $((EXPRESSION))'.
            @_,
        );
    },

    # ` COMMAND `
    sub {
        my $file = shift;
        check_pattern(
            $file,
            '\`.*\`',
            "Severity $HARSH at $file:LINE_NUMBER: "
                . '`COMMANDS` is an older form of the command substitution. The usage of the POSIX-form $(COMMANDS) is preferred.',
            @_,
        );
    },

    # function keyword
    sub {
        my $file = shift;
        check_pattern(
            $file,
            'function\ *'.$NAME_PATTERN.'\ *{',
            "Severity $STERN at $file:LINE_NUMBER: "
                . 'The "function NAME { ...; }" form of the function definition is not recommended simply use NAME() { ...; } to define a function.',
            @_,
        );
    },

    # let EXPRESSION
    sub {
        my $file = shift;
        check_pattern(
            $file,
            'let\ ',
            "Severity $HARSH at $file:LINE_NUMBER: "
                . '"let MATH" is the classic form of the arithmetic evaluation command. Bash has an own compound command for that, which should be used if possible: ": $((MATH))."',
            @_,
        );
    },

    ############
    # Formatting

    # lines too long
    sub {
        my $file    = shift;
        my @lines   = read_file($file);
        my $counter = 0;
        for my $line (@lines) {
            $counter++;
            if (length $line > 78) {
                print "Severity $CRUEL at $file:$counter: "
                    . "line is longer than 78 characters, consider splitting it over multiple lines to increase readability.\n";
            }
        }
    }


    
);

for my $file (@FILES) {
    perform_checks($file);
}

1;

__END__
