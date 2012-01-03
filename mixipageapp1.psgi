use strict;
use warnings;

use MixiPageApp1;

my $app = MixiPageApp1->apply_default_middlewares(MixiPageApp1->psgi_app);
$app;

