# Some tests

# these should not generate a warning

# function a {}
a=1; # function a {}
s="function a {}"
s='function a {}'
s='
function a {}'
afunction a {}
$function a {}

# these should generate a warning

function a {}
function a {} # function a {}
s='string'; function a {}
s="string"; function a {}
s="'#'"; function a {}
s='"#"'; function a {}
s='\'#"'; function a {}
s="\"#'"; function a {}
s='#'; function a {}
s='\#'; function a {}
s="#"; function a {}
s="\#"; function a {}
grep \# file; function a {}
s='string #'; function a {}
