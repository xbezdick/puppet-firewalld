# here you can see how to create a zone configuration
# see also firewalld.zone(5) man page

# run 'puppet resource firewalld_zone' to see the current zone config
#
# run this with 'puppet apply zone.pp'

class { '::firewalld::configuration':
  default_zone => 'custom',
}

# define a zone
firewalld::zone { 'custom':
  description   => 'This is an example zone',
  services      => ['ssh', 'dhcpv6-client'],
  masquerade    => true,
  ports         => [{
    port     => '1234',
    protocol => 'tcp',
  },],
  forward_ports => [{
    port     => '123',
    protocol => 'tcp',
    to_port  => '321',
    to_addr  => '1.2.3.4',
  },],
  rich_rules    => [{
    family      => 'ipv4',
    source      => {
      address => '1.1.1.1',
      invert  => true,
    },
    destination => {
      address => '2.2.2.2/24',
    },
    port        => {
      portid   => '123-321',
      protocol => 'udp',
    },
    log         => {
      prefix => 'testing',
      level  => 'notice',
      limit  => '3/s',
    },
    audit       => {
      limit => '2/h',
    },
    action      => {
      action_type => 'reject',
      reject_type => 'icmp-host-prohibited',
      limit       => '2/m',
    },
  },],
}
