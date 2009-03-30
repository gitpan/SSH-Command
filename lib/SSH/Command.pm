package SSH::Command;

use strict;
use warnings;

use Carp;
use Data::Dumper;
use File::Temp;
use Scope::Guard;
use Net::SSH2;
use Exporter::Lite;

our $DEBUG = 0;
our $VERSION = '0.04';

our @EXPORT     = qw/ssh_execute/;

=head1 NAME

SSH::Command - interface to execute multiple commands
on host by SSH protocol without certificates ( only login + password )

=head1 SYNOPSIS

 use SSH::Command;

 my $result = ssh_execute(
    host     => '127.0.0.1',
    username => 'suxx',
    password => 'qwerty',
    commands =>
        [
            {
                cmd    => 'uname -a', # for check connection
                verify => qr/linux/i, # or  => 'linux-....' (check by 'eq')
            }
        ]
    );

 if ($result) {
    print "all ok!";
 } else {
    print "Command failed!";
 }

=cut

#
# Module Net::SSH2 have troubles with Perl 5.10
# use this patch http://rt.cpan.org/Public/Bug/Display.html?id=36614
# and patch Net::SSH2
#

# Convert server answer in raw ormat to string
# unpacking LIBSSH2_HOSTKEY_HASH_MD5 struct
sub raw_to_string {
    my ($raw) = @_;
    return join '', map { sprintf "%x", ord $_ } split '|', $raw;
}

# Sub for working with server over ssh / scp
sub ssh_execute {
    my %params = @_;    

    #require_once 'Net::SSH2';
    my $ssh2 = Net::SSH2->new();

    print "Start connection\n" if $DEBUG;

    unless ($params{host} && $ssh2->connect($params{host})) {
        die "SSH connection failed or host not specified!";
        return '';
    } else {
        print "Connection established" if $DEBUG;
    }   
    
    # classical password auth
    if ($params{password} && $params{username}) {
        $ssh2->auth_password( $params{username}, $params{password} );
    } elsif ($params{key_path}) {
        # auth by cert not supported
        die "Certificate auth in progress!";
        return '';
    } else {
        die "Not enought data for auth!";
        return '';
    }

    # check auth result
    if ($ssh2->auth_ok) {
        if ($params{hostkey}) { # check server fingerprint
            if (raw_to_string($ssh2->hostkey('md5')) ne lc $params{hostkey}) {
                die "Server digest verification failed!";
                return '';
            }
        }
    
        my $sg = Scope::Guard->new( sub { $ssh2->disconnect } );

        if ( ref $params{commands} eq 'ARRAY' ) {
            foreach my $command (@{ $params{commands} }) {

                if (ref $command        eq 'HASH'    &&
                    $command->{cmd}     eq 'scp_put' &&
                    $command->{string}               &&
                    $command->{dest_path} 
                ) {
                    my $temp_file = File::Temp->new;

                    $temp_file->printflush($command->{string});
                    $temp_file->seek(0, 0);
                    #print $temp_file->getlines; -- work very unstable!
                    unless ( $command->{dest_path} =~ m#^/(?:var|tmp)# ) {
                        die "Danger! Upload only in /var or /tmp";
                        return '';
                    }

                    unless($ssh2->scp_put($temp_file, $command->{dest_path})) {
                        die "Scp put failed!";
                        return '';
                    }
                } else {
                    my $chan = $ssh2->channel();
                    my $result;
        
                    $chan->exec($command->{cmd});
                    $chan->read($result, 1000);
                    chomp $result; # remove \n on string tail
    
                    if ( ref $command->{verify} eq 'Regexp' ) {
                        if ($result !~ /$command->{verify}/) {
                            die "Server answer ($result) is not match reg ex!";
                            return '';
                        }
                    } elsif ($command->{verify}) {
                        if ($result ne $command->{verify}) {
                            die "Server answer ($result) is not equal " .
                                "verify string ($command->{verify})!";
                            return '';
                        }
                    } else {
                        die "Verify string is null!";
                        return '';
                    }

                }
            }
        }

        return 1; # all ok
    } else {
        die "SSH authorization failed!";
        return '';
    }
}

sub wrapper {
    # Put config data to YAML config
    my $user_dir_path   = "/var/www/vhosts/test_domain/httpdocs";
    my $config_path     = "user_dir/cfg/config.ini";
    my $sql_dump_file   = "user_dir/install/dump.sql";
    my $dist_path       = '/var/rpanel/r_0.1042_nrg.tar.bz2';
    my $config          = { }; # STUB

    ssh_execute(
        host     => 'rpanels_ssh_host',
        username => 'rpanels_ssh_username',
        password => 'rpanels_ssh_password',
        hostkey  => 'rpanels_ssh_host_digest',
        commands => [
            {
                cmd    => 'uname -a',     # for connect check
                verify => qr/linux/i,
            },

            {
                cmd    => "tar -xjf $dist_path "     .
                          "-C $user_dir_path && echo 'ok'",
                verify => 'ok'
            },

            {
                cmd       => 'scp_put',
                string    => 'some data',
                dest_path => '/tmp/some_path',
            },

            {
                cmd    => "chmod a+rwx $config_path && echo 'ok_chmod'",
                verify => 'ok_chmod',
            },

            {
                cmd    => "zcat $sql_dump_file.gz > " .
                          "$sql_dump_file && echo 'ok_zcat'",
                verify => 'ok_zcat',
            },

            {
                cmd  => "mysql -u$config->{db_user} -p$config->{db_user_password}" .
                    " -D$config->{db_name} < $sql_dump_file && echo 'ok_sql_init'",
                verify => 'ok_sql_init',
            },

            {
                cmd       => 'scp_put', 
                dest_path => "${sql_dump_file}_create_admin.sql",
                string    => "
                    SET NAMES 'cp1251';
                    INSERT INTO admin (email, passwd, first_name,last_name, support_phone, support_icq, support_email)
                    VALUES(
                        '$config->{email}',
                        MD5('$config->{passwd}'),
                        '$config->{first_name}',
                        '$config->{last_name}',
                        '$config->{support_phone}',
                        '$config->{support_icq}',
                        '$config->{support_email}'
                        );
                "
            },

            {
                cmd    => "mysql -u$config->{db_user} -p$config->{db_user_password} " .
                    "-D$config->{db_name} < ${sql_dump_file}_create_admin.sql && echo 'create_admin_ok'",
                verify => 'create_admin_ok',
            },

            {
                cmd    => "rm -rf $user_dir_path/install && echo 'ok_rm'",
                verify => 'ok_rm',
            },
        ],
    ) or return 'FAIL';
}


1;

__END__
        # Simple analogue of Scope::Guard
        my $close_handles_object = eval {
            package XXX::DestroyObject;

            sub new {
                my $class = shift;
                           
                return bless { object => shift, method => shift }, $class;
            }

            sub DESTROY {
                my $self = shift;
                
                my $object = $self->{object};
                my $method = $self->{method};

                #print "close handles!";
                return $object->$method;
            }
            __PACKAGE__
        }->new($ssh2, 'disconnect');

