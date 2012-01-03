package MixiPageApp1::OAuthUtil::SignedRequest;

use strict;
use warnings;

use Crypt::OpenSSL::CA;
use OAuth::Lite::ServerUtil;

use URI;
use URI::QueryParam;

# set CA
my $mixi_ca_pc = << '__CERTIFICATE__';
-----BEGIN CERTIFICATE-----
MIIDfDCCAmSgAwIBAgIJAIzC8GwwTFzxMA0GCSqGSIb3DQEBBQUAMDIxCzAJBgNV
BAYTAkpQMREwDwYDVQQKEwhtaXhpIEluYzEQMA4GA1UEAxMHbWl4aS5qcDAeFw0x
MTA1MjQwNTMxMTBaFw0xMzA1MjMwNTMxMTBaMDIxCzAJBgNVBAYTAkpQMREwDwYD
VQQKEwhtaXhpIEluYzEQMA4GA1UEAxMHbWl4aS5qcDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAMbpHo2BGgxSDO9jQmFoWEwscPJV/96LMtBNq7qm3NuD
8vX8Y1zF5VTKzpOhlX9uvOMrmOaWkMnPcQK2WxbocyB6lCF3Ewv41dR3lfR3oVbX
mF9tx+lLDYxyp5qoDzk/aOIgh0YHbwGuWwP8/kCwd2wUuXO6qMEEEOrqIafmGJdZ
KKFWwNSV8h4K1/guP4XK3gwTeiawJzYcKwHM+tMHAZax58HPr7lMbN0DGeeNXjW9
dNKqYjRw9XcTtv9ZQIcSvU+9c/dZHk3cm963vrxvtVsA4V/VSBaf6X0WJ44am//c
954poRVR0TA/4X76ZIgEKT12/H1MVJn4rQsrGtK4U68CAwEAAaOBlDCBkTAdBgNV
HQ4EFgQUVrpcuj6H3rI0IU7ZDBhIC7dCshwwYgYDVR0jBFswWYAUVrpcuj6H3rI0
IU7ZDBhIC7dCshyhNqQ0MDIxCzAJBgNVBAYTAkpQMREwDwYDVQQKEwhtaXhpIElu
YzEQMA4GA1UEAxMHbWl4aS5qcIIJAIzC8GwwTFzxMAwGA1UdEwQFMAMBAf8wDQYJ
KoZIhvcNAQEFBQADggEBAAkOHmJINcm8UEQWWSuYjIiwA/xSuFJKpGqSe3VAn2Gm
4W9seLN14duuu/CsNL31ih1jnSrYtzlOdmVwUOeYi5yhyHNkWtw1wSOQA8i+IFCt
WKXsxYyPblKjsNB9x3VyFSZYw+v41mVFQQGDH4V1JwyJW9Aebffv6oKROTkaIdt/
J5YoB712zHKVm0rZue3eUHdMiSIJLzhR6bL2bKV13wGSeKf7RBX/9lFTSVsyc9MQ
vjAOYWeGFYpup624CGWKPG+PEQe7vaDycaFHd0TPgoxLukUHkZhxvXo+tiweKnwI
WcfqZCQCnoPfIDIoVWFdMw6T9hJLICb5a8f05k1JFoQ=
-----END CERTIFICATE-----
__CERTIFICATE__

my $mixi_ca_touch = << '__CERTIFICATE__';
-----BEGIN CERTIFICATE-----
MIIDfDCCAmSgAwIBAgIJALlFXlCiAFLyMA0GCSqGSIb3DQEBBQUAMDIxCzAJBgNV
BAYTAkpQMREwDwYDVQQKEwhtaXhpIEluYzEQMA4GA1UEAxMHbWl4aS5qcDAeFw0x
MTA3MDYwMTE5MjJaFw0xMzA3MDUwMTE5MjJaMDIxCzAJBgNVBAYTAkpQMREwDwYD
VQQKEwhtaXhpIEluYzEQMA4GA1UEAxMHbWl4aS5qcDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAN21pHE0zoW5NF+0Qd0h10Lc+obTnn6uKV247xezGam5
vP0+729zo0Ch46abF9B5SUIk3/kFfrwWU73UB8j9GJPcx6dN/SB4C/EpYPanbK7N
FohgLPh+uihB3brOfe0fCYQUzfh5lgfzzHyNxR7vE5ErVvQH2YMC1dX0LnE70m3y
+8QTQpq0My2FvttBAZwr2wV4mG/xuvxR3sXtzkTf7DLkRXCcuImMrRd+AI8oi9sG
xfB8ThFekgc9TARVgUiCgC/RNrIWmwh2s7ivCFDRPMfTJlNGTTu10SegS6+1cZgY
93/2fzsIUl86nxaNmLAu3+nzct/364lIwSB9/8hvsiUCAwEAAaOBlDCBkTAdBgNV
HQ4EFgQUqvQ+ztpLlBlv27Tmj+cXZn+7s/0wYgYDVR0jBFswWYAUqvQ+ztpLlBlv
27Tmj+cXZn+7s/2hNqQ0MDIxCzAJBgNVBAYTAkpQMREwDwYDVQQKEwhtaXhpIElu
YzEQMA4GA1UEAxMHbWl4aS5qcIIJALlFXlCiAFLyMAwGA1UdEwQFMAMBAf8wDQYJ
KoZIhvcNAQEFBQADggEBADDwaSXWL755GVQ5hcWEQGAQZFIpK1LSUuup0i2cRwAF
QnQE5cyQcQuy2qE7+dqSz6RHtRW4fnaJygPmpM912xjdG0Hbo/grKbrkVrpa1Hg5
Oi1ffKBUhT9ygttv/FxJDy3d7wqHgQXPT/Qkp1VJE6q24uKDHyEB/FiL01lbgZWm
73pSvRPXTBr2CY21SfPfhLzQoulr4KYx57U9C8BJoNJKXoHgOZ00NbDcc8VyB59H
RPtjxzf6g1yUOuefBoshCryaixWqmIUmv6RcE3ZGB5MCyJi8K3qo0Keo2W7HBH0t
NW1Lho60tFXYbHDeXiYlw3dT+R+al9zojfOUB3sJ/vU=
-----END CERTIFICATE-----
__CERTIFICATE__

my $public_key;

sub validate {
    my $req = shift;

    if ( $req->param('xoauth_signature_publickey') and $req->param('oauth_signature') ) {

        my $method = $req->method;
        my $url = $req->uri;
        my $params = $req->params;

        my $util = OAuth::Lite::ServerUtil->new();
        $util->support_signature_method('RSA_SHA1');

        my $ca = ( substr($req->param('xoauth_signature_publickey'), 0, 7) eq 'page_pc' ) ? $mixi_ca_pc : $mixi_ca_touch;
        $public_key = Crypt::OpenSSL::CA::X509->parse($ca)
                      ->get_public_key()
                      ->to_PEM();

        my $ret = $util->verify_signature(
                      method          => $method,
                      url             => $url,
                      params          => $params,
                      consumer_secret => $public_key,
                  );
        return $ret;
    }else{
        return 0;
    }
}

1;
