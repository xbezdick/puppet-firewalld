require 'spec_helper_acceptance'

describe 'firewalld class' do
  context 'simple firewall' do
    it 'should work with no errors' do
      pp= <<-EOS
      firewalld::zone { 'guca':
        description => 'Mine',
        rich_rules => [{
          family => 'ipv4',
          source => { address => '192.168.1.1', invert => false},
          service => 'dns',
          action => { action_type => 'accept', }
        }],
        services    => ['ssh', 'dhcpv6-client', 'dns', 'https', 'kerberos', 'http', 'kpasswd', 'ldap', 'ldaps', 'ntp'],
      }
      firewalld::zone { 'usata':
        description => 'Mine',
        rich_rules => [{
          family => 'ipv4',
          source => { address => '192.168.1.1', invert => false},
          service => 'dns',
          action => { action_type => 'accept', }
        }],
        services    => ['ssh', 'dhcpv6-client', 'dns', 'https', 'kerberos', 'http', 'kpasswd', 'ldap', 'ldaps', 'ntp'],
      }
      class { 'firewalld::configuration':
        default_zone => 'usata',
      }
      EOS

      # Run it twice and test for idempotency
      apply_manifest(pp, :catch_failures => true)
      apply_manifest(pp, :catch_changes => true)
    end
  end
end
