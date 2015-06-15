#!/usr/bin/env ruby
require "rubygems"
require "r509"
require "r509/trollop"
require "r509/certificateauthority/http/version"

opts = R509::Trollop.options do
  opt :cert, "File name from load CA certificate", :type => :string,
    :required => true
  opt :key, "File name from load CA private key", :type => :string,
    :required => true
  opt :config, "File name to save configuration", :type => :string,
    :required => true
  version "ca-config.rb #{R509::CertificateAuthority::HTTP::VERSION}"
end

puts "Build CA configuration file."

CA = "private"
PROFILE = "test"

# http://stackoverflow.com/questions/14616686/
#   how-do-i-add-additional-information-to-certificate-service-request-csr
# http://www.alvestrand.no/objectid/2.5.4.html
# N.B. La configurazione delle proprieta' long_name sembra causare dei problemi
# di riconoscimento del campo a OpenSSL; in ogni caso, la visualizzazione del
# certificato mostra la descrizione standard associata al campo.
# L'estensione subject_item_policy deve far riferimento alla proprieta'
# short_name cosi' come l'impostazione dei campi del soggetto.

additional_subject_fields = [
    { :oid => "2.5.4.4", :short_name => "surname" },
    { :oid => "2.5.4.5", :short_name => "SN" },
    { :oid => "2.5.4.42", :short_name => "name" }
]
R509::OIDMapper.batch_register(additional_subject_fields)

cert_pem = File.read(opts[:cert])
key_pem = File.read(opts[:key])
cert = R509::Cert.new(:cert => cert_pem, :key => key_pem)

config = R509::Config::CAConfig.new( { :ca_cert => cert,
    :crl_list_file => "list.txt",
    :crl_number_file => "crlnumber.txt",
    :crl_md => "SHA1"
} )

profile = R509::Config::CertProfile.new(
    :basic_constraints => R509::Cert::Extensions::BasicConstraints.new(
        :ca => false, :critical => false
    ),
    :key_usage => R509::Cert::Extensions::KeyUsage.new(
        :critical => true,
        :value => [ "digitalSignature", "nonRepudiation", "keyEncipherment",
            "dataEncipherment" ]
    ),
    :extended_key_usage => R509::Cert::Extensions::ExtendedKeyUsage.new(
        :value => [ "clientAuth", "emailProtection" ]
    ),
    :certificate_policies =>
        R509::Cert::Extensions::CertificatePolicies.new(:value => [ {
            :policy_identifier => "1.3.76.33.1.1.15",
            :cps_uris => [ "http://ca/tipki.it/TTCollPRIVCA/CPS" ],
            :user_notices => [ { :explicit_text => "Certificato dimostrativo " +
                "di Firma Elettronica Avanzata" } ]
        } ]),
#    :ocsp_no_check => nil,
#    :inhibit_any_policy => nil,
#    :policy_constraints => nil,
#    :authority_info_access => nil,
    :crl_distribution_points =>
        R509::Cert::Extensions::CRLDistributionPoints.new(
            :value => [ { :type => "URI",
                :value => "http://ca.tipki.it/TTCollPRIVCA/CDP1" } ]
        ),
#    :name_constraints => nil,
    :subject_item_policy => R509::Config::SubjectItemPolicy.new(
        "CN" => { :policy => "required" },
        "C" => { :policy => "match", :value => "IT" },
        "O" => { :policy => "match", :value => "Private Company" },
        "OU" => { :policy => "match",
            :value => "Secure CA Trust" },
        "emailAddress" => { :policy => "optional" },
        "surname" => { :policy => "required" },
        "name" => { :policy => "required" },
        "SN" => { :policy => "required" },
    ),
    :default_md => "SHA1",
    :allowed_mds => [ "SHA1", "SHA256", "SHA512" ]
)

config.set_profile(PROFILE, profile)

pool = R509::Config::CAConfigPool.new(CA => config)

pool_hash = pool.to_h
cert_hash = pool_hash[CA]["ca_cert"]
cert_hash["cert"] = opts[:cert]
cert_hash["key"] = opts[:key]

resp = { "custom_oids" => additional_subject_fields,
    "certificate_authorities" => pool_hash }
File.open(opts[:config], "w") do |f|
    f.write(resp.to_yaml)
end
