package MixiPageApp1::OAuthUtil::Resource;

use strict;
use warnings;

use HTTP::Request;
use LWP::UserAgent;
use JSON;
use URI::Escape;

sub get_page_info{
    my ($access_token, $page_id) = @_;

    # build request
    my $endpoint = sprintf(q{https://api.mixi-platform.com/2/pages/%s}, $page_id);
    my $req = HTTP::Request->new( GET => $endpoint );
    $req->header( Authorization => sprintf(q{OAuth %s}, $access_token) );

    # get response
    my $res = LWP::UserAgent->new->request($req);
    return decode_json($res->content);
}	

sub get_user_info{
    my $access_token = shift;

    # build request
    my $endpoint = q{https://api.mixi-platform.com/2/people/@me/@self};
    my $req = HTTP::Request->new( GET => $endpoint );
    $req->header( Authorization => sprintf(q{OAuth %s}, $access_token) );

    # get response
    my $res = LWP::UserAgent->new->request($req);
    return decode_json($res->content);
}	

sub post_voice{
    my ($access_token, $message) = @_;

    # build request
    my $endpoint = q{https://api.mixi-platform.com/2/voice/statuses/update};
    my $req = HTTP::Request->new( POST => $endpoint );
    $req->header( Authorization => sprintf(q{OAuth %s}, $access_token) );
    $req->content_type('application/x-www-form-urlencoded');
    $req->content('status='.uri_escape($message));
    	
    # get response
    my $res = LWP::UserAgent->new->request($req);
    return decode_json($res->content);
}

1;
