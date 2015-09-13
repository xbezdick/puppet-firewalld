require 'puppet'
require File.expand_path(File.join(File.dirname(__FILE__), '..', 'firewalld'))
require 'rexml/document'
include REXML


Puppet::Type.type(:firewalld_zonefile).provide :zoneprovider, :parent => Puppet::Provider::Firewalld do
  @doc = "The zone config manipulator"

  commands :firewall => 'firewall-cmd'
  commands :iptables => 'iptables'

  attr_accessor :destroy_zone

  mk_resource_methods

  def flush
    Puppet.debug "firewalld zonefile provider: flushing (#{@resource[:name]})"
    write_zonefile unless destroy_zone
  end

  def create
    Puppet.debug "firewalld zonefile provider: create (#{@resource[:name]})"
    write_zonefile
  end

  def write_zonefile
    Puppet.debug "firewalld zonefile provider: write_zonefile (#{@resource[:name]})"
    doc = REXML::Document.new
    zone = doc.add_element 'zone'
    doc << REXML::XMLDecl.new(version='1.0',encoding='utf-8')

    if @resource[:target] && ! @resource[:target].empty?
      zone.add_attribute('target', @resource[:target])
    end

    if @resource[:short]
      short = zone.add_element 'short'
      short.text = @resource[:short]
    end

    if @resource[:description]
      description = zone.add_element 'description'
      description.text = @resource[:description]
    end

    if @resource[:interfaces]
      @resource[:interfaces].each do |interface|
        begin
          zoneofinterface = exec_firewall('--get-zone-of-interface', interface)
          if (zoneofinterface.strip != @resource[:name])
            exec_firewall('--permanent', '--zone', zoneofinterface.strip, '--remove-interface', interface)
            exec_firewall('--zone', @resource[:name], '--change-interface', interface)
          end
        rescue Exception => bang
          #puts bang.message
        end

        iface = zone.add_element 'interface'
        iface.add_attribute('name', interface)
      end
    end

    if @resource[:sources]
      @resource[:sources].each do |source|
        # TODO: firewall-cmd --get-zone-of-source...
        src = zone.add_element 'source'
        src.add_attribute('address', source)
      end
    end

    if @resource[:services]
      @resource[:services].each do |service|
        srv = zone.add_element 'service'
        srv.add_attribute('name', service)
      end
    end

    if @resource[:ports]
      @resource[:ports].each do |port|
        prt = zone.add_element 'port'
        prt.add_attribute('port', port['port'])
        prt.add_attribute('protocol', port['protocol'])
      end
    end

    if @resource[:icmp_blocks]
      @resource[:icmp_blocks].each do |icmp_block|
        iblk = zone.add_element 'icmp-block'
        iblk.add_attribute('name', icmp_block)
      end
    end

    if @resource[:masquerade]
      if @resource[:masquerade] == :true
        zone.add_element 'masquerade'
      end
    end

    if @resource[:forward_ports]
      @resource[:forward_ports].each do |forward_port|
        fw_prt = zone.add_element 'forward-port'
        fw_prt.add_attribute('port', forward_port['port'])
        fw_prt.add_attribute('protocol', forward_port['protocol'])
        if forward_port['to_port']
          fw_prt.add_attribute('to-port', forward_port['to_port'])
        end
        if forward_port['to_addr']
          fw_prt.add_attribute('to-addr', forward_port['to_addr'])
        end
      end
    end

    if @resource[:rich_rules]
      @resource[:rich_rules] = @resource[:rich_rules].uniq
      @resource[:rich_rules].flatten.each do |rich_rule|
        rule = zone.add_element 'rule'
        if rich_rule['family']
          rule.add_attribute('family', rich_rule['family'])
        end

        if rich_rule['source']
          source = rule.add_element 'source'
          source.add_attribute('address', rich_rule['source']['address'])
          source.add_attribute('invert', rich_rule['source']['invert'])
        end

        if rich_rule['destination']
          dest = rule.add_element 'destination'
          dest.add_attribute('address', rich_rule['destination']['address'])
          dest.add_attribute('invert', rich_rule['destination']['invert'])
        end

        if rich_rule['service']
          service = rule.add_element 'service'
          service.add_attribute('name', rich_rule['service'])
        end

        if rich_rule['port']
          port = rule.add_element 'port'
          port.add_attribute('port', rich_rule['port']['portid'])
          port.add_attribute('protocol', rich_rule['port']['protocol'])
        end

        if rich_rule['protocol']
          protocol = rule.add_element 'protocol'
          protocol.add_attribute('value', rich_rule['protocol'])
        end

        if rich_rule['icmp_block']
          icmp_block = rule.add_element 'icmp-block'
          icmp_block.add_attribute('name', rich_rule['icmp_block'])
        end

        if rich_rule['masquerade']
          rule.add_element 'masquerade'
        end

        if rich_rule['forward_port']
          fw_port = rule.add_element 'forward-port'
          fw_port.add_attribute('port', rich_rule['forward_port']['portid'])
          fw_port.add_attribute('protocol', rich_rule['forward_port']['protocol'])
          if rich_rule['forward_port']['to_port']
            fw_port.add_attribute('to-port', rich_rule['forward_port']['to_port'])
          end
          if rich_rule['forward_port']['to_addr']
            fw_port.add_attribute('to-addr', rich_rule['forward_port']['to_addr'])
          end
        end

        if rich_rule['log']
          log = rule.add_element 'log'
          if rich_rule['log']['prefix']
            log.add_attribute('prefix', rich_rule['log']['prefix'])
          end
          if rich_rule['log']['level']
            log.add_attribute('level', rich_rule['log']['level'])
          end
          if rich_rule['log']['limit']
            limit = log.add_element 'limit'
            limit.add_attribute('value', rich_rule['log']['limit'])
          end
        end

        if rich_rule['audit']
          audit = rule.add_element 'audit'
          if rich_rule['audit']['limit']
            limit = audit.add_element 'limit'
            limit.add_attribute('value', rich_rule['audit']['limit'])
          end
        end

        if rich_rule['action']
          action = rule.add_element rich_rule['action']['action_type']
          if rich_rule['action']['reject_type']
            action.add_attribute('type', rich_rule['action']['reject_type'])
          end
          if rich_rule['action']['limit']
            limit = action.add_element 'limit'
            limit.add_attribute('value', rich_rule['action']['limit'])
          end
        end
      end
    end

    path = '/etc/firewalld/zones/' + @resource[:name] + '.xml'
    file = File.open(path, "w+")
    fmt = REXML::Formatters::Pretty.new
    fmt.compact = true
    fmt.write(doc, file)
    file.close
    Puppet.debug "firewalld zonefile provider: Changes to #{path} configuration saved to disk."
    #Reload is now done from a notify command in the puppet code

    # TEMPORARY: FIXME:
    # We are doing `firewall-cmd --reload` here because we broke notify metaparam in 1.0.0 release on clients using a puppet master
    # We will be fixing this breakage soon enough, but until then, this will suffice.
    exec_firewall('--reload')
  end

  # Utilized code from crayfishx/puppet-firewalld as the firewall-cmd needs it's arguments properly formatted
  # This function does it well
  # Use example: exec_firewall('--permanent', '--zone', zonevar, '--remove-interface', interfacevar)
  def exec_firewall(*extra_args)
    args=[]
    args << extra_args
    args.flatten!
    firewall(args)
  end

  def self.instances
    # We do not want any instances in this resource as it's a combiner
    []
  end

  def destroy
    path = '/etc/firewalld/zones/' + @resource[:name] + '.xml'
    File.delete(path)
    Puppet.debug "firewalld zonefile provider: removing (#{path})"
    @destroy_zone = true
    @property_hash.clear
  end

  def exists?
    if resource[:target] == nil
      resource[:target] = ''
    end
    @property_hash[:ensure] == :present || false
  end

  # Prefetch xml data.
  # This prefetch is special to zonefile as it does consistency checking
  def self.prefetch(resources)
    Puppet.debug "firewalld prefetch instance: #{instances}"
    parse_zonefiles.each do |prov|
      Puppet.debug "firewalld prefetch instance resource: (#{prov.name})"
      if resource = resources[prov.name]
        resource.provider = prov
        # Checking for consistency here so it's not called during `puppet resource` rather only on puppet runs
        unless prov.consistent?
          Puppet.warning("Found IPTables is not consistent with firewalld's zones, we will reload firewalld to attempt to restore consistency.  If this doesn't fix it, you must have a bad zone XML")
          firewall('--reload')
          unless prov.consistent?
            raise Puppet::Error("Bad zone XML found, check your zone configuration")
          end
        end
      end
    end
  end

  def consistent?
    iptables_allow = []
    iptables_deny = []
    firewallcmd_accept = []
    firewallcmd_deny = []
    begin
      iptables_allow = iptables('-L', "IN_#{@resource[:name]}_allow", '-n').split("\n")
      iptables_allow.delete_if { |val| ! val.start_with?("ACCEPT") }
    rescue
    end

    begin
      iptables_deny = iptables('-L', "IN_#{@resource[:name]}_deny", '-n').split("\n")
      iptables_deny.delete_if { |val| ! val.start_with?("DROP", "REJECT") }
    rescue
    end

    begin
      firewallcmd = firewall("--zone=#{@resource[:name]}", '--list-all').split("\n")
      firewallcmd.select! { |val| /\srule family/ =~ val }
      firewallcmd_exp = firewallcmd.map do |val|
        arr = []
        if /service name=\"(.*?)\"/ =~ val
          if service_ports = read_service_ports($1)
            service_ports.each do |port|
              arr << val.sub(/(service name=\".*?\")/, "\\1 port=#{port}")
            end
          end
        end
        arr.empty? ? val : arr
      end

      firewallcmd_exp.flatten!

      firewallcmd_accept = firewallcmd_exp.select { |val| /accept\Z/ =~ val }
      firewallcmd_deny = firewallcmd_exp.select { |val| /reject\Z|drop\Z/ =~ val }
    rescue
    end


    unless iptables_allow.count == firewallcmd_accept.count && iptables_deny.count == firewallcmd_deny.count
      Puppet.debug("Consistency issue between iptables and firewalld zone #{@property_hash[:name]}:\niptables_allow.count: #{iptables_allow.count}\nfirewallcmd_accept.count: #{firewallcmd_accept.count}\niptables_deny.count: #{iptables_deny.count}\nfirewallcmd_deny.count: #{firewallcmd_deny.count}")
    end

    # Technically the IPTables allow list and the firewallcmd_accept list(as well as deny lists) numbering lines up
    # and we could do a regex comparison to verify that the EXACT values existed if we wanted to iptables_allow[index] =~ /...firewallcmd_accept[index].../ for example
    iptables_allow.count == firewallcmd_accept.count && iptables_deny.count == firewallcmd_deny.count
  end

  def read_service_ports(service_name)
    file = if File.exist?("/etc/firewalld/services/#{service_name}.xml")
             File.open("/etc/firewalld/services/#{service_name}.xml")
           elsif File.exist?("/usr/lib/firewalld/services/#{service_name}.xml")
             File.open("/usr/lib/firewalld/services/#{service_name}.xml")
           end
    return false unless file
    doc = REXML::Document.new(file)
    ports = []
    doc.root.elements.each("port") do |ele|
      ports << "#{ele.attributes["port"]}/#{ele.attributes["protocol"]}"
    end
    file.close
    ports
  end
end
