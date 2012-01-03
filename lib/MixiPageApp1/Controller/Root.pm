package MixiPageApp1::Controller::Root;
use Moose;
use namespace::autoclean;

use MixiPageApp1::OAuthUtil::SignedRequest;
use MixiPageApp1::OAuthUtil::AccessToken;
use MixiPageApp1::OAuthUtil::Resource;
use MixiPageApp1::Session;
use URI::Escape;

BEGIN { extends 'Catalyst::Controller' }

#
# Sets the actions in this controller to be registered with no prefix
# so they function identically to actions created in MyApp.pm
#
__PACKAGE__->config(namespace => '');

=head1 NAME

MixiPageApp1::Controller::Root - Root Controller for MixiPageApp1

=head1 DESCRIPTION

[enter your description here]

=head1 METHODS

=head2 logout

The logout page (/logout)

- clear user data in session
- redirect back to root page

=cut

sub logout : Global {
    my ( $self, $c ) = @_;

    # logout
    MixiPageApp1::Session::clear_user($c->session);

    # Redirect to top page
    my $param_page_id = uri_unescape($c->req->param('mixi_page_id') || '');
    my $param_sig = uri_unescape($c->req->param('sig') || '');
    $c->res->redirect("/?mixi_page_id=".uri_escape($param_page_id).
                 "&sig=".uri_escape($param_sig));
    return;
}

=head2 voice

Voice page (/voice)

- validate signature and session
- send request to voice API
- redirect back to root page

=cut

sub voice : Global {
    my ( $self, $c ) = @_;

    my $param_page_id = uri_unescape($c->req->param('mixi_page_id') || '');
    my $param_sig = uri_unescape($c->req->param('sig') || '');
    my $isValidOriginalRequest = MixiPageApp1::Session::validate_page_id($c->session, $c->req);
    if ( $isValidOriginalRequest ) {
        # Validate original signature
        $isValidOriginalRequest = MixiPageApp1::Session::validate_signature(
                                      $c->session, 
                                      $c->req,
                                      $c->config
                                  );
    }

    my $param_status = $c->req->param('voicemsg') || '';
    my $access_token_str = MixiPageApp1::Session::get_access_token($c->session);
    if ( $isValidOriginalRequest and $access_token_str and $param_status ) {
        # post voice
        my $post_response = MixiPageApp1::OAuthUtil::Resource::post_voice(
                                $access_token_str, 
                                $param_status
                            );
        # update session
        MixiPageApp1::Session::update_session($c->session);
        $param_sig = MixiPageApp1::Session::calcuate_signature($c->session, $c->config);
    } 
    $c->res->redirect("/?mixi_page_id=".uri_escape($param_page_id)."&sig=".uri_escape($param_sig));
    return;
}

=head2 default

The Root page (/)

- validate signature and session
- send request to page API
- view page

=cut

sub default : Private {
    my ( $self, $c ) = @_;

    my $param_page_id = uri_unescape($c->req->param('mixi_page_id') || '');
    my $param_sig = uri_unescape($c->req->param('sig') || '');
    my $isValidOriginalRequest = MixiPageApp1::Session::validate_page_id($c->session, $c->req);
    if ( !$isValidOriginalRequest ) {
        # Invalid Request : Destroy Session
        MixiPageApp1::Session::clear_session($c->session);
    }else{
        # Validate original signature
        $isValidOriginalRequest = MixiPageApp1::Session::validate_signature(
                                      $c->session, 
                                      $c->req,
                                      $c->config
                                  );
    }

    # Validate normal OAuth signeture
    my $isValidReq = MixiPageApp1::OAuthUtil::SignedRequest::validate($c->req) ;

    if ( $isValidOriginalRequest or $isValidReq ){

        if ( $isValidReq ) {
            MixiPageApp1::Session::set_page_id($c->session, $c->req);
        }
        MixiPageApp1::Session::update_session($c->session);
        $param_sig = MixiPageApp1::Session::calcuate_signature($c->session, $c->config);

        my $access_token_client = MixiPageApp1::OAuthUtil::AccessToken::get_from_clientcredentials($c->config);
        my $page_info = MixiPageApp1::OAuthUtil::Resource::get_page_info(
                            $access_token_client->access_token, 
                            $param_page_id
                        );

        # Set variables and template
        $c->stash->{appId} = $c->config->{client_id};
        $c->stash->{facebook_appId} = $c->config->{facebook_appId};
        $c->stash->{page_id} = $param_page_id;
        $c->stash->{raw_sig} = $param_sig;
        $c->stash->{sig} = uri_escape($param_sig);
        $c->stash->{user_id} = MixiPageApp1::Session::get_user_id($c->session);
        $c->stash->{displayName} = MixiPageApp1::Session::get_displayName($c->session);
        $c->stash->{page_url} = "http://page.mixi.jp/view_page.pl?page_id=".$param_page_id;
        $c->stash->{page_displayName} = $page_info->{entry}->{displayName};
        $c->stash->{template} = 'Root.tmpl';

        # ToDo : Logging
        # 
    }else{
        # Display Error Tenplate
        $c->stash->{template} = 'Error.tmpl';

        # ToDo : Logging
        # 
    }
}

=head2 end

Attempt to render a view, if needed.

=cut

sub end : ActionClass('RenderView') {}

=head1 AUTHOR

Ryo Ito

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

__PACKAGE__->meta->make_immutable;

1;
