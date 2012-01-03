package MixiPageApp1::OAuthUtil::AccessToken;

use strict;
use warnings;

use OAuth::Lite2::Client::ClientCredentials;
use OAuth::Lite2::Client::WebServer;

sub get_from_clientcredentials {
    my $config = shift;

    my $client = OAuth::Lite2::Client::ClientCredentials->new(
        id               => $config->{client_id},
        secret           => $config->{client_secret},
        access_token_uri => q{https://secure.mixi-platform.com/2/token} 
    );

    my $access_token = $client->get_access_token() or return 0;
    return $access_token;
}

sub get_from_authorizationcode {
    my ($config, $code) = @_;

    my $client = OAuth::Lite2::Client::WebServer->new(
        id               => $config->{client_id},
        secret           => $config->{client_secret},
        authorize_uri     => q{https://mixi.jp/connect_authorize.pl},
        access_token_uri => q{https://secure.mixi-platform.com/2/token} 
    );
    my $redirect_uri = "http://59.106.187.116:5000/authorization/callback/";

    my $access_token = $client->get_access_token(
        code         => $code,
        redirect_uri => $config->{redirect_uri}
    ) or return 0;
    return $access_token;
}

1;
