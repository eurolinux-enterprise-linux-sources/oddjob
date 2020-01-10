#!/usr/bin/python
import oddjob
print oddjob.call_method(oddjob.default_object(), oddjob.default_interface(), "list")
print oddjob.call_method(oddjob.default_object(), oddjob.default_interface(), "bogus")
