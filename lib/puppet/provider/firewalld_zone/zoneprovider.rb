require 'puppet'
require File.expand_path(File.join(File.dirname(__FILE__), '..', 'firewalld'))
require 'rexml/document'
include REXML

Puppet::Type.type(:firewalld_zone).provide :zoneprovider, :parent => Puppet::Provider::Firewalld do
  @doc = "The zone config manipulator"

  mk_resource_methods

  def flush
    # Does nothing, handled in firewalld_zonefile provider
  end

  def create
    # Does nothing, handled in firewalld_zonefile provider
  end

  def destroy
    # Does nothing, handled in firewalld_zonefile provider
  end

  def exists?
    @property_hash[:ensure] == :present || false
  end

  # Prefetch xml data.
  def self.prefetch(resources)
    Puppet.debug "firewalld prefetch instance: #{instances}"
    instances.each do |prov|
      Puppet.debug "firewalld prefetch instance resource: (#{prov.name})"
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end
end
