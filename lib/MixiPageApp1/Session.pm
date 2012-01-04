package MixiPageApp1::Session;

use strict;
use warnings;

use URI::Escape;
use OAuth::Lite2::Signer::Algorithm::HMAC_SHA256;
use MIME::Base64;

sub clear_user{
    my $session = shift;
    delete $session->{user_id};
    delete $session->{displayName};
    delete $session->{access_token};
    delete $session->{refresh_token};
    delete $session->{expires_in};
}

sub clear_session{
    my $session = shift;
    delete $session->{page_id};
    delete $session->{updated};
    clear_user($session);
}

sub get_access_token{
    my $session = shift;
    return $session->{access_token} || '';
}

sub get_user_id{
    my $session = shift;
    return $session->{user_id} || '';
}

sub get_displayName{
    my $session = shift;
    return uri_unescape($session->{displayName} || '');
}

sub get_page_id{
    my $session = shift;
    return $session->{page_id} || '';
}

sub get_expires_in{
    my $session = shift;
    return $session->{expires_in} || 0;
}

sub get_refresh_token{
    my $session = shift;
    return $session->{refresh_token} || '';
}

sub set_user_info{
    my ( $session, $user_info ) = @_;
    $session->{user_id} = $user_info->{entry}->{id} || '';
    $session->{displayName} = uri_escape_utf8($user_info->{entry}->{displayName} || '');
}

sub set_access_token{
    my ( $session, $access_token ) = @_;
    $session->{access_token} = $access_token->access_token;
    $session->{expires_in} = int($access_token->expires_in) + time;
    if (defined($access_token->refresh_token)) {
        $session->{refresh_token} = $access_token->refresh_token;
    }
}

sub set_page_id{
    my ( $session, $req ) = @_;
    $session->{page_id} = uri_unescape($req->param('mixi_page_id') || '');
}

sub update_session{
    my ( $session ) = @_;
    $session->{updated} = time;
}

sub calcuate_signature{
    my ( $session, $config ) = @_;
    my $algorithm = OAuth::Lite2::Signer::Algorithm::HMAC_SHA256->new;
    return MIME::Base64::encode_base64(
               $algorithm->hash(
                   $config->{signature_key},
                   $session->{page_id}.$session->{updated}
               ),
               ''
           );
}

# validate page_id
sub validate_page_id{
    my ( $session, $req ) = @_;
    my $param_page_id = uri_unescape($req->param('mixi_page_id') || '');
    my $session_page_id = $session->{page_id} || '';
    if ( !$param_page_id or ( $param_page_id ne $session_page_id )   ){
        return 0;
    }
    return 1;
}

# validate user_id
sub validate_user_id{
    my ( $session, $req ) = @_;
    my $param_viewer_id = uri_unescape($req->param('mixi_viewer_id') || '');
    my $session_user_id = $session->{user_id} || '';
    if ( !$param_viewer_id or ( $param_viewer_id ne $session_user_id ) ){
        return 0;
    }
    return 1;
}

# Validate original signature
sub validate_signature{
    my ( $session, $req, $config ) = @_;
    my $param_page_id = uri_unescape($req->param( 'mixi_page_id') || '' );
    my $param_sig = uri_unescape( $req->param('sig') || '' );
    if ( $param_sig ) {
        my $calculated_sig = calcuate_signature( $session, $config );
        if ( $param_sig eq $calculated_sig ) {
            return 1;
        }
    }
    return 0;
}

1;
