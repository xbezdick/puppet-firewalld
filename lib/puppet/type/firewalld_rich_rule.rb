require 'puppet'

class Hash
  def deep_sort
    Hash[sort.map {|k, v| [k, v.is_a?(Hash) ? v.deep_sort : v]}]
  end
end

Puppet::Type.newtype(:firewalld_rich_rule) do
  desc <<-EOT
          Rich language rule (firewalld.richlanguage(5)
          You have to specify one (and only one)
          of service, port, protocol, icmp_block, masquerade, forward_port
          and one (and only one) of accept, reject, drop
  EOT

  ensurable do
    defaultvalues

    defaultto { :present }
  end

  def exists?
    self[:ensure] == :present
  end

  newparam(:name) do
    desc "The name of the zone to add rich rule to"
  end

  newparam(:zone) do
    desc "The name of the zone to add rich rule to"
  end

  newparam(:rich_rules, :array_matching => :all) do
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
    defaultto ([])

    def munge(s)
      if !s.nil? or !s.empty?
        if s.is_a?(Hash)
          [s.deep_sort]
        else
          s.map! { |x| x.deep_sort }
        end
      else
        [s]
      end
    end



    def insync?(is)
      return true
      def itos(h)
        h.each { |key, value|
          h[key] = itos(value) if value.is_a?(Hash)
          h[key] = value.to_s if value.is_a?(Integer)
        }
      end
      if is.is_a?(Array) and @should.is_a?(Array)
        @should.each { |should_el|
          itos(should_el)
          break unless is.detect { |is_el| is_el == should_el }
        }
      else
        is == @should
      end
    end
  end

  autorequire(:firewalld_zone) do
    catalog.resources.collect do |r|
      r.name if r.is_a?(Puppet::Type.type(:firewalld_zone)) && r[:name] == self[:zone]
    end.compact
  end

end
