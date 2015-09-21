require 'puppet'
require 'puppet/property'
require 'puppet/property/boolean'

class Hash
  def deep_sort
    Hash[sort.map {|k, v| [k, v.is_a?(Hash) ? v.deep_sort : v]}]
  end
end

Puppet::Type.newtype(:firewalld_zone) do
  desc <<-EOT
      = Define: firewalld::zone

      This defines a zone configuration.
      Result is a /etc/firewalld/zones/${name}.xml file, where ${name}
      is name of the class. See also firewalld.zone (5) man page.

      === Examples

       firewalld::zone { "custom":
          description  => "This is an example zone",
          services     => ["ssh", "dhcpv6-client"],
          sources      => ["10.0.0.8", "192.168.18.22", "2001:DB8:0:f00d:/64", ],
          ports        => [
            {
                  port        => "1234",
                  protocol    => "tcp",
            },
          ],
          masquerade    => true,
          forward_ports => [
            {
                  port        => '123',
                  protocol    => 'tcp',
                  to_port     => '321',
                  to_addr     => '1.2.3.4',
            },
          ],
          rich_rules    => [
            {
                  family        => 'ipv4',
                  source        => {
                      address       => '192.168.1.0/24',
                      invert        => true,
                  },
                  port          => {
                      portid      => '123-321',
                      protocol    => 'udp',
                  },
                  log        => {
                      prefix       => 'local',
                      level        => 'notice',
                      limit        => '3/s',
                  },
                  audit        => {
                      limit        => '2/h',
                  },
                  action        => {
                      action_type    => 'reject',
                      reject_type    => 'icmp-host-prohibited',
                  },
            },
          ],
       }
  EOT

  def munge_boolean(value)
    case value
    when true, "true", :true
      :true
    when false, "false", :false
      :false
    else
      fail("munge_boolean only takes booleans")
    end
  end

  ensurable do
    defaultvalues

    defaultto { :present }
  end

  #def exists?
  #  self[:ensure] == :present
  #end

  newparam(:name) do
    desc "The name of the zone"
    validate do |value|
      unless value =~ /^[A-Za-z0-9_]+$/
        raise(ArgumentError, "Invalid zone name: #{name}")
      end
      if value.length > 17
        raise(ArgumentError, "Zone name longer than 17 characters: #{name}")
      end
    end
    isnamevar
  end

  newproperty(:target) do
    desc <<-EOT
      Can be one of {'ACCEPT', '%%REJECT%%', 'DROP'}.
      Used to accept, reject or drop every packet that
      doesn't match any rule (port, service, etc.).
      Default (when target is not specified) is reject.
    EOT
    newvalues('ACCEPT', '%%REJECT%%', 'DROP', '')
    def insync?(is)
        return true
    end
  end

  newproperty(:short) do
      desc "short readable name"
      def insync?(is)
        true
      end
  end

  newproperty(:description) do
      desc "long description of zone"
      def insync?(is)
        true
      end
  end

  newproperty(:interfaces, :array_matching => :all) do
      desc "list of interfaces to bind to a zone"
      def insync?(is)
        return true
        self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
        if @should.empty? && is == :absent then
          return true
        end

        if match_all? then
          return false unless is.is_a? Array
          return false unless is.length == @should.length
          return (is == @should or is == @should.map(&:to_s))
        else
          return @should.any? {|want| property_matches?(is, want) }
        end
      end
  end

  newproperty(:sources, :array_matching => :all) do
      desc <<-EOT
        list of source addresses or source address
        ranges ("address/mask") to bind to a zone
      EOT
      def insync?(is)
        return true
        self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
        if @should.empty? && is == :absent then
          return true
        end

        if match_all? then
          return false unless is.is_a? Array
          return false unless is.length == @should.length
          return (is == @should or is == @should.map(&:to_s))
        else
          return @should.any? {|want| property_matches?(is, want) }
        end
      end
  end

  newproperty(:ports, :array_matching => :all) do
      desc <<-EOT
        list of ports to open
          ports  => [
            {
              port     => mandatory, string, e.g. '1234'
              protocol => mandatory, string, e.g. 'tcp'
            },
            ...
          ]
      EOT
      def insync?(is)
        return true
        self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
        if @should.empty? && is == :absent then
          return true
        end

        if match_all? then
          return false unless is.is_a? Array
          return false unless is.length == @should.length
          return (is == @should or is == @should.map(&:to_s))
        else
          return @should.any? {|want| property_matches?(is, want) }
        end
      end
  end

  newproperty(:services, :array_matching => :all) do
      desc "list of predefined firewalld services"

      def insync?(is)
        return true
        self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
        if @should.empty? && is == :absent then
          return true
        end

        if match_all? then
          return false unless is.is_a? Array
          return false unless is.length == @should.length
          return (is == @should or is == @should.map(&:to_s))
        else
          return @should.any? {|want| property_matches?(is, want) }
        end
      end
  end

  newproperty(:icmp_blocks, :array_matching => :all) do
      desc "list of predefined icmp-types to block"
      def insync?(is)
        return true
        self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
        if @should.empty? && is == :absent then
          return true
        end

        if match_all? then
          return false unless is.is_a? Array
          return false unless is.length == @should.length
          return (is == @should or is == @should.map(&:to_s))
        else
          return @should.any? {|want| property_matches?(is, want) }
        end
      end
   end

  newproperty(:masquerade, :boolean => true) do
      desc "enable masquerading ?"
      newvalues(true, false)
      defaultto false
      munge do |value|
        @resource.munge_boolean(value)
      end

      def insync?(is)
        return true
        self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
        if @should.empty? && is == :absent then
          return true
        end

        if match_all? then
          return false unless is.is_a? Array
          return false unless is.length == @should.length
          return (is == @should or is == @should.map(&:to_s))
        else
          return @should.any? {|want| property_matches?(is, want) }
        end
      end
  end

  newproperty(:forward_ports, :array_matching => :all) do
      desc <<-EOT
        list of ports to forward to other port and/or machine
          forward_ports  => [
            {
              port     => mandatory, string, e.g. '123' or '123-125'
              protocol => mandatory, string, e.g. 'tcp'
              to_port  => mandatory to specify either to_port or/and to_addr
              to_addr  => mandatory to specify either to_port or/and to_addr
            },
            ...
          ]
      EOT
      def insync?(is)
        return true
        self.devfail "#{self.class.name}'s should is not array" unless @should.is_a?(Array)
        if @should.empty? && is == :absent then
          return true
        end

        if match_all? then
          return false unless is.is_a? Array
          return false unless is.length == @should.length
          return (is == @should or is == @should.map(&:to_s))
        else
          return @should.any? {|want| property_matches?(is, want) }
        end
      end
  end

  newproperty(:rich_rules, :array_matching => :all) do
      desc <<-EOT
        list of rich language rules (firewalld.richlanguage(5))
          You have to specify one (and only one)
          of service, port, protocol, icmp_block, masquerade, forward_port
          and one (and only one) of accept, reject, drop

            family - 'ipv4' or 'ipv6', optional, see Rule in firewalld.richlanguage(5)

            source  => {  optional, see Source in firewalld.richlanguage(5)
              address  => mandatory, string, e.g. '192.168.1.0/24'
              invert   => optional, bool, e.g. true
            }

            destination => { optional, see Destination in firewalld.richlanguage(5)
              address => mandatory, string
              invert  => optional, bool, e.g. true
            }

            service - string, see Service in firewalld.richlanguage(5)

            port => { see Port in firewalld.richlanguage(5)
              portid   => mandatory
              protocol => mandatory
            }

            protocol - string, see Protocol in firewalld.richlanguage(5)

            icmp_block - string, see ICMP-Block in firewalld.richlanguage(5)

            masquerade - bool, see Masquerade in firewalld.richlanguage(5)

            forward_port => { see Forward-Port in firewalld.richlanguage(5)
              portid   => mandatory
              protocol => mandatory
              to_port  => mandatory to specify either to_port or/and to_addr
              to_addr  => mandatory to specify either to_port or/and to_addr
            }

            log => {   see Log in firewalld.richlanguage(5)
              prefix => string, optional
              level  => string, optional
              limit  => string, optional
            }

            audit => {  see Audit in firewalld.richlanguage(5)
              limit => string, optional
            }

            action => {  see Action in firewalld.richlanguage(5)
              action_type => string, mandatory, one of 'accept', 'reject', 'drop'
              reject_type => string, optional, use with 'reject' action_type only
              limit       => string, optional
            }
      EOT
      defaultto([])

      def munge(s)
        #puts "MUNGE #{s.inspect}"
        if s == :absent
          return []
        end
        if !s.nil? or !s.empty?
          if s.is_a?(Hash)
            [s.deep_sort]
          else
            s.map! { |x| x.deep_sort }
          end
        else
          if s.is_a?(Hash)
            s.deep_sort
          else
            [s]
          end
        end
      end

      def insync?(is)
        true
      end
  end

  autorequire(:file) do
    ["/etc/firewalld/zones/#{self[:name]}.xml"]
  end
  autorequire(:firewalld_rich_rule) do
    catalog.resources.collect do |r|
      r.name if r.is_a?(Puppet::Type.type(:firewalld_rich_rule)) && r[:zone] == self[:name]
    end.compact
  end

  def should_content
    return @generated_content if @generated_content
    @generated_content = ""
    rich_rules = []

    resources = catalog.resources.select do |r|
      r.is_a?(Puppet::Type.type(:firewalld_rich_rule)) && r[:zone] == self[:name]
    end

    resources.each do |r|
      rich_rules << r[:rich_rules]
    end

    @generated_content = rich_rules.flatten

    @generated_content
  end

  def generate
    file_opts = {
      :ensure => self[:ensure] == :absent ? :absent : :present,
    }

    [:name, :target, :short, :description, :interfaces, :sources, :ports, :services, :icmp_blocks, :masquerade, :forward_ports ].each do |param|
      unless self[param].nil?
        file_opts[param] = self[param]
      end
    end
      file_opts[:rich_rules] = self[:rich_rules] #unless self[:rich_rules].nil? or self[:rich_rules].empty?
    [ Puppet::Type.type(:firewalld_zonefile).new(file_opts) ]
  end

  def eval_generate
    content = should_content
    if !content.nil? and !content.empty?
      content << [self[:rich_rules]] if !self[:rich_rules].nil? and !self[:rich_rules].empty?
      catalog.resource("Firewalld_zonefile[#{self[:name]}]")[:rich_rules] = content.flatten
    end
    [ catalog.resource("Firewalld_zonefile[#{self[:name]}]") ]
  end

end

