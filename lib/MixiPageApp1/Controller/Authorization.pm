package MixiPageApp1::Controller::Authorization;

use Moose;
use namespace::autoclean;

use MixiPageApp1::OAuthUtil::AccessToken;
use MixiPageApp1::OAuthUtil::Resource;
use MixiPageApp1::Session;
use URI::Escape;

BEGIN {extends 'Catalyst::Controller'; }

=head1 NAME

MixiPageApp1::Controller::Authorization - Catalyst Controller

=head1 DESCRIPTION

Catalyst Controller.

=head1 METHODS

=cut

=head2 callback

OAuth 2.0 callback page (/authorization/callback)

- get access token
- send request to people API
- set access token and user info to session
- redirect back to Root page

=cut

sub callback :Local {
    my ( $self, $c ) = @_;

    my $param_code = $c->request->param('code');
    my $param_state = $c->request->param('state');
#    my $session_page_id = $c->session->{page_id} || '';
    my $session_page_id = MixiPageApp1::Session::get_page_id($c->session);
    my $calculated_sig = MixiPageApp1::Session::calcuate_signature($c->session, $c->config);
    if ( !$session_page_id or ( $param_state ne $calculated_sig ) ) {
        $c->stash->{template} = 'Error.tmpl'; 
    }else{
        # Update session
        MixiPageApp1::Session::update_session($c->session);
        my $param_sig = MixiPageApp1::Session::calcuate_signature($c->session, $c->config);
        my $access_token;
        if( $param_code ){
            $access_token = MixiPageApp1::OAuthUtil::AccessToken::get_from_authorizationcode($c->config, $param_code);
        }

        if(defined($access_token)){
            my $user_info = MixiPageApp1::OAuthUtil::Resource::get_user_info(
                            $access_token->access_token
                        );
            # Set profile data to session
            MixiPageApp1::Session::set_user_info($c->session, $user_info);

            # Set authrization data to session
            MixiPageApp1::Session::set_access_token($c->session, $access_token);
        }
        $c->res->redirect("/?mixi_page_id=".uri_escape($c->session->{page_id})."&sig=".uri_escape($param_sig));
        return;
    }
}

=head1 AUTHOR

Ryo Ito

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;
