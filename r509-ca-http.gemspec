$:.push File.expand_path("../lib", __FILE__)
require "r509/certificateauthority/http/version"

spec = Gem::Specification.new do |s|
  s.name = 'r509-ca-http'
  s.version = R509::CertificateAuthority::Http::VERSION
  s.platform = Gem::Platform::RUBY
  s.has_rdoc = false
  s.summary = "A (relatively) simple certificate authority API written to work with r509"
  s.description = 'A CA API. What, you want more info?'
  s.add_dependency 'r509'
  s.add_dependency 'sinatra'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'rack-test'
  s.add_development_dependency 'rake'
  s.add_development_dependency 'rcov' if RUBY_VERSION.split('.')[1].to_i == 8
  s.add_development_dependency 'simplecov' if RUBY_VERSION.split('.')[1].to_i == 9
  s.author = "Sean Schulte"
  s.email = "sirsean@gmail.com"
  s.homepage = "http://vikinghammer.com"
  s.required_ruby_version = ">= 1.8.6"
  s.files = %w(README.md Rakefile) + Dir["{lib,script,spec,doc,cert_data}/**/*"]
  s.test_files= Dir.glob('test/*_spec.rb')
  s.require_path = "lib"
end

