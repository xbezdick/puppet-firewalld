#!/bin/bash
set -ev
rake lint
rake syntax
# we can't ssh to localhost
#rspec spec/acceptance
