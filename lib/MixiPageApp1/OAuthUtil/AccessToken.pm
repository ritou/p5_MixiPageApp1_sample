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

    my $access_token = $client->get_access_token() or return '';

    return $access_token;
}

sub get_from_authorizationcode {
    my ($config, $code) = @_;

    my $client = OAuth::Lite2::Client::WebServer->new(
        id               => $config->{client_id},
        secret           => $config->{client_secret},
        authorize_uri    => q{https://mixi.jp/connect_authorize.pl},
        access_token_uri => q{https://secure.mixi-platform.com/2/token} 
    );

    my $access_token = $client->get_access_token(
        code         => $code,
        redirect_uri => $config->{redirect_uri}
    ) or return '';

    return $access_token;
}

sub get_from_refreshtoken {
    my ($config, $refresh_token) = @_;

    my $client = OAuth::Lite2::Client::WebServer->new(
        id               => $config->{client_id},
        secret           => $config->{client_secret},
        authorize_uri    => q{https://mixi.jp/connect_authorize.pl},
        access_token_uri => q{https://secure.mixi-platform.com/2/token} 
    );

    my $access_token = $client->refresh_access_token(
        refresh_token => $refresh_token,
    ) or return '';

    return $access_token;
}

1;
