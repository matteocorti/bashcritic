# Load the Module::Install bundled in ./inc/
use inc::Module::Install;

##############################################################################
# Define metadata (we read it from the binary)

name     'bashcritic';
all_from 'bashcritic';

##############################################################################
# Specific dependencies

include 'version';

requires 'Data::Dumper'    => 0;
requires 'File::Slurp'     => 0;
requires 'English'         => 0;
requires 'Getopt::Long'    => 0;
requires 'Pod::Usage'      => 0;
requires 'List::Util'      => 0;
requires 'List::MoreUtils' => 0;
requires 'version';

install_script  'bashcritic';

auto_install;

WriteAll;
