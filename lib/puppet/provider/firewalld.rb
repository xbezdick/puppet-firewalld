class Hash
  def deep_sort
    Hash[sort.map {|k, v| [k, v.is_a?(Hash) ? v.deep_sort : v]}]
  end
end

class Puppet::Provider::Firewalld < Puppet::Provider

  # Prefetch xml data.
  def self.prefetch(resources)
    debug("[prefetch(resources)]")
    Puppet.debug "firewalld prefetch instance: #{instances}"
    instances.each do |prov|
      Puppet.debug "firewalld prefetch instance resource: (#{prov.name})"
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end

  # Clear out the cached values.
  def flush
    @property_hash.clear
  end

  # This allows us to conventiently look up existing status with properties[:foo].
  def properties
    if @property_hash.empty?
      @property_hash[:ensure] = :absent
    end
    @property_hash.dup
  end

  def self.instances
    parse_zonefiles
  end

  def self.parse_zonefiles
    debug "[instances]"
    zonefiles = Dir["/etc/firewalld/zones/*.xml"]

    zone = []

    zonefiles.each do |path|
      zonename = File.basename(path, ".xml")
      doc = REXML::Document.new File.read(path)
      target = ''
      version = ''
      short = ''
      description = ''
      interface = []
      source = []
      service = []
      ports = []
      icmp_blocks = []
      masquerade = false
      forward_ports = []
      rich_rules = []

      # Set zone level variables
      root = doc.root
      # Go to next file if there is not a doc.root
      if ! root
        next
      end
      target = root.attributes["target"]
      version = root.attributes["version"]

      # Loop through the zone elements
      doc.elements.each("zone/*") do |e|

        if e.name == 'short'
          short = e.text.to_s.strip
        end
        if e.name == 'description'
          description = e.text.to_s.strip
        end
        if e.name == 'interface'
          interface << e.attributes["name"]
        end
        if e.name == 'source'
          source << e.attributes["address"]
        end
        if e.name == 'service'
          service << e.attributes["name"]
        end
        if e.name == 'port'
          ports << {
            'port' => e.attributes["port"].nil? ? nil : e.attributes["port"],
            'protocol' => e.attributes["protocol"].nil? ? nil : e.attributes["protocol"],
          }
        end
        if e.name == 'icmp-block'
          icmp_blocks << e.attributes["name"]
        end
        if e.name == 'masquerade'
          masquerade = :true
        end
        if e.name == 'forward-port'
          forward_ports << {
            'port' => e.attributes["port"].nil? ? nil : e.attributes['port'],
            'protocol' => e.attributes["protocol"].nil? ? nil : e.attributes["protocol"],
            'to_port' => e.attributes["to-port"].nil? ? nil : e.attributes["to-port"],
            'to_addr' => e.attributes["to-addr"].nil? ? nil : e.attributes["to-addr"],
          }
        end

        if e.name == 'rule'

            rule_source = {}
            rule_destination = {}
            rule_service = ''
            rule_ports = {}
            rule_protocol = ''
            rule_icmp_blocks = ''
            rule_masquerade = false
            rule_forward_ports = {}
            rule_log = {}
            rule_audit = {}
            rule_action = {}
            # Changed rule_family to blank to start as it is an optional variable and should be treated as such for consistency
            rule_family = ''

            # family is a rule attribute rather than an element and therefore must happen prior to the elements loop
            rule_family = e.attributes["family"].nil? ? nil : e.attributes["family"]

          e.elements.each do |rule|
            if rule.name == 'source'
              rule_source['address'] = rule.attributes["address"]
              if rule.attributes["invert"] == 'true'
                rule_source['invert'] = true
              else
                rule_source['invert'] = rule.attributes["invert"].nil? ? nil : false
              end
              rule_source.delete_if { |key,value| key == 'invert' and value == nil}

            end
            if rule.name == 'destination'
              rule_destination['address'] = rule.attributes["address"]
              if rule.attributes["invert"] == 'true'
                rule_destination['invert'] = true
              else
                rule_destination['invert'] = rule.attributes["invert"].nil? ? nil : false
              end
              rule_destination.delete_if { |key,value| key == 'invert' and value == nil}
            end
            if rule.name == 'service'
              rule_service = rule.attributes["name"]
            end
            if rule.name == 'port'
              rule_ports['portid'] = rule.attributes["port"].nil? ? nil : rule.attributes["port"]
              rule_ports['protocol'] = rule.attributes["protocol"].nil? ? nil : rule.attributes["protocol"]
            end
            if rule.name == 'protocol'
              rule_protocol = rule.attributes["value"]
            end
            if rule.name == 'icmp-block'
              rule_icmp_blocks = rule.attributes["name"]
            end
            if rule.name == 'masquerade'
              rule_masquerade = true
            end
            if rule.name == 'forward-port'
              rule_forward_ports['portid'] = rule.attributes["port"].nil? ? nil : rule.attributes["port"]
              rule_forward_ports['protocol'] = rule.attributes["protocol"].nil? ? nil : rule.attributes["protocol"]
              rule_forward_ports['to_port'] = rule.attributes["to-port"].nil? ? nil : rule.attributes["to-port"]
              rule_forward_ports['to_addr'] = rule.attributes["to-addr"].nil? ? nil : rule.attributes["to-addr"]
            end
            if rule.name == 'log'
              begin
                limit = rule.elements["limit"].attributes["value"]
              rescue
                limit = nil
              end
              rule_log['prefix'] = rule.attributes["prefix"].nil? ? nil : rule.attributes["prefix"]
              rule_log['level'] = rule.attributes["level"].nil? ? nil : rule.attributes["level"]
              rule_log['limit'] = limit
            end
            if rule.name == 'audit'
              rule_audit['limit'] = rule.elements["limit"].attributes["value"].nil? ? nil : rule.elements["limit"].attributes["value"]
            end
            if rule.name == 'accept'
              begin
                limit = rule.elements["limit"].attributes["value"]
              rescue
                limit = nil
              end
              rule_action['action_type'] = rule.name
              rule_action['reject_type'] = nil
              rule_action['limit'] = limit
            end
            if rule.name == 'reject'
              begin
                limit = rule.elements["limit"].attributes["value"]
              rescue
                limit = nil
              end
              rule_action['action_type'] = rule.name
              rule_action['reject_type'] = rule.attributes["type"].nil? ? nil : rule.attributes["type"]
              rule_action['limit']  = limit
            end
            if rule.name == 'drop'
              begin
                limit = rule.elements["limit"].attributes["value"]
              rescue
                limit = nil
              end
              rule_action['action_type'] = rule.name
              rule_action['reject_type'] = nil
              rule_action['limit']  = limit
            end
          end
          rich_rules << {
            'source'        => rule_source.empty? ? nil : rule_source,
            'destination'   => rule_destination.empty? ? nil : rule_destination,
            'service'       => rule_service.empty? ? nil : rule_service,
            'port'          => rule_ports.empty? ? nil : rule_ports,
            'protocol'      => rule_protocol.empty? ? nil : rule_protocol,
            'icmp_block'    => rule_icmp_blocks.empty? ? nil : rule_icmp_blocks,
            'masquerade'    => rule_masquerade.nil? ? nil : rule_masquerade,
            'forward_port'  => rule_forward_ports.empty? ? nil : rule_forward_ports,
            'log'           => rule_log.empty? ? nil : rule_log,
            'audit'         => rule_audit.empty? ? nil : rule_audit,
            'action'        => rule_action.empty? ? nil : rule_action,
            'family'        => rule_family.empty? ? nil : rule_family,
          }

        end

        # remove services if not set so the data type matches the data type returned by the puppet resource.
        rich_rules.each do |rr|

          # This will recursively remove any hashes that have nil values
          # We must still specify special items like masquerade because it's false rather than nil
          p = proc do |_, v|
            v.delete_if(&p) if v.respond_to? :delete_if
            v.nil? #|| v.respond_to?(:"empty?") && v.empty?
          end
          rr.delete_if(&p)

          rr.delete_if { |key,value| key == 'masquerade' and value == false}

          rr = rr.deep_sort
        end
        # We run a deep hash sort outside of the each block so that it can take direct effect without having to write a new variable
        rich_rules.map! { |rr| rr.deep_sort }
      end

      ## convert the masquerade variable from boolean to array so the data type matches the data type returned by the puppet resource.
      #if masquerade
      #  masquerade = ['true']
      #else
      #  masquerade = ['false']
      #end

      # Add hash to the zone array
      zone << new({
        :name          => zonename,
        :ensure        => :present,
        :target        => target.nil? ? nil : target,
        :version       => version.nil? ? nil : version,
        :short         => short.nil? ? nil : short,
        :description   => description.nil? ? nil : description,
        :interfaces    => interface.empty? ? nil : interface,
        :sources       => source.empty? ? nil : source,
        :services      => service.empty? ? nil : service,
        :ports         => ports.empty? ? nil : ports,
        :icmp_blocks   => icmp_blocks.empty? ? nil : icmp_blocks,
        :masquerade    => masquerade == false ? :false : masquerade,
        :forward_ports => forward_ports.empty? ? nil : forward_ports,
        :rich_rules    => rich_rules.empty? ? nil : rich_rules,
      })

    end
    zone
  end

end
