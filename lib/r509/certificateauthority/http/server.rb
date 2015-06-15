
require 'sinatra/base'
require 'r509'
require "#{File.dirname(__FILE__)}/config"
require "#{File.dirname(__FILE__)}/subjectparser"
require "#{File.dirname(__FILE__)}/validityperiodconverter"
require "#{File.dirname(__FILE__)}/factory"
require 'base64'
require 'yaml'
require 'logger'
require 'dependo'
require 'json'

# Capture USR2 calls so we can reload and print the config
# I'd rather use HUP, but daemons like thin already capture that
# so we can't use it.
Signal.trap("USR2") do
  R509::CertificateAuthority::HTTP::Config.load_config
  R509::CertificateAuthority::HTTP::Config.print_config
end

module R509
  module CertificateAuthority
    module HTTP
      class Server < Sinatra::Base
        extend Dependo::Mixin
        include Dependo::Mixin

        # CA 
        CA = "private"

        # Codifica dei messaggi
        MESSAGE_DIGEST = "sha256"

        # Tipo di chiave di default
        KEYTYPE_DEF = "RSA"

        # Numero di bit delle chiavi di default
        KEYLEN_DEF = 2048

        # Curva EC di default
        ECCURVE_DEF = "secp384r1"

        configure do
          disable :protection #disable Rack::Protection (for speed)
          disable :logging
          set :environment, :production

          set :subject_parser,
            R509::CertificateAuthority::HTTP::SubjectParser.new
          set :validity_period_converter,
            R509::CertificateAuthority::HTTP::ValidityPeriodConverter.new
          set :csr_factory,
            R509::CertificateAuthority::HTTP::Factory::CSRFactory.new

          # Configurato thin come HTTP server perche' quello utilizzato di
          # default da Sinatra (WEBrick, tra l'altro, pare come implementazione
          # interna in Sinatra) non accetta richieste POST con body vuoto.
          set :server, 'thin'
        end

        before do
          content_type :text
        end

        helpers do
          def ca(name)
            Dependo::Registry[:certificate_authorities][name]
          end
          def builder(name)
            Dependo::Registry[:options_builders][name]
          end
          def subject_parser
            settings.subject_parser
          end
          def validity_period_converter
            settings.validity_period_converter
          end
          def csr_factory
            settings.csr_factory
          end
          def print_pem?
              Dependo::Registry[:print_pem] == true
          end
        end

        error do
          log.error env["sinatra.error"].inspect
          log.error env["sinatra.error"].backtrace.join("\n")
          "Something is amiss with our CA. You should ... wait?"
        end

        error StandardError do
          log.error env["sinatra.error"].inspect
          log.error env["sinatra.error"].backtrace.join("\n")
          env["sinatra.error"].inspect
        end

        get '/1/ca/cert/?' do
            ca_config = Dependo::Registry[:config_pool][CA]
            if not ca_config
                raise R509::R509Error, "CA #{CA} not found"
            end

            ca_config.ca_cert.to_pem
        end

        get '/1/ca/profiles/?' do
            ca_config = Dependo::Registry[:config_pool][CA]
            if not ca_config
                raise R509::R509Error, "CA #{CA} not found"
            end

            ca_hash = ca_config.to_h
            if ca_hash.has_key?("profiles")
                profile_map = ca_hash["profiles"]
                v = profile_map.keys
            else
                v = []
            end

            resp = { :items => v }

            content_type :json
            resp.to_json
        end

        post '/1/keypair/?' do
            key = generate_key(params)

            if print_pem?
                pem = key.to_pem + key.public_key.to_pem
                pem
            else
                resp = { :privatekey => key.to_pem,
                    :publickey => key.public_key.to_pem }

                content_type :json
                resp.to_json
            end
        end

        post '/1/certificate/request/sign/?' do
            raw = request.env["rack.input"].read
            env["rack.input"].rewind

            csr = sign_request(raw, params)

            csr.to_pem
        end

        post '/1/certificate/request/?' do
            raw = request.env["rack.input"].read
            env["rack.input"].rewind

            csr = generate_request(raw, params)

            csr.to_pem
        end

        post '/1/certificate/signedrequest/?' do
            raw = request.env["rack.input"].read
            env["rack.input"].rewind

            resp = generate_signed_request(raw, params)
            csr = resp[:csr]

            if resp.key?(:privatekey)
                key = resp[:privatekey]
            else
                key = nil
            end

            if key.nil?
                csr.to_pem
            elsif print_pem?
                pem = csr.to_pem + key.to_pem + key.public_key.to_pem
                pem
            else
                resp = { :csr => csr.to_pem, :privatekey => key.to_pem,
                    :publickey => key.public_key.to_pem }

                content_type :json
                resp.to_json
            end
        end

        post '/1/certificate/issue/?' do
            raw = request.env["rack.input"].read
            env["rack.input"].rewind

            if not ca(CA)
                raise R509::R509Error, "CA #{CA} not found"
            end
            if not params.has_key?("profile")
                raise ArgumentError, "Must provide a CA profile"
            end

            if not params.has_key?("validityPeriod")
                raise ArgumentError, "Must provide a validity period"
            end
            validity_period = validity_period_converter.convert(
                params["validityPeriod"])

            key = nil
            if params.has_key?("csr")
                csr = csr_factory.build(:csr => params["csr"])
            else
                resp = generate_signed_request(raw, params)
                csr = resp[:csr]
                if resp.key?(:privatekey)
                    key = resp[:privatekey]
                end
            end
		
	    #todo: Add parametric san_names

	    san_names = [{:type=> 'otherName', :value => "2.5.4.20;PRINTABLESTRING:3394400394"},{:type=>'otherName', :value => "2.5.4.45;BITSTRING:3839333930303130303030313239303030303033390"},{:type=>'email', :value=> "3394400394@tim.it"}]
	    ext = []
	    ext << R509::Cert::Extensions::BasicConstraints.new(:ca => false)
	    ext << R509::Cert::Extensions::SubjectAlternativeName.new(:value => san_names)
	    #END


            signer_opts = builder(CA).build_and_enforce(:csr => csr,
                :profile_name => params["profile"],
                :message_digest => MESSAGE_DIGEST,
                :not_before => validity_period[:not_before],
                :not_after => validity_period[:not_after],
                #:extensions => list_request_extensions(csr))
		:extensions => ext)
            cert = ca(CA).sign(signer_opts)

            if key.nil?
                cert.to_pem
            elsif print_pem?
                pem = cert.to_pem + key.to_pem + key.public_key.to_pem
                pem
            else
                resp = { :cert => cert.to_pem, :privatekey => key.to_pem,
                    :publickey => key.public_key.to_pem }

                content_type :json
                resp.to_json
            end
        end

        private

        def load_public_key(params)
            data = params[:public_key]
            password = nil
            # OpenSSL::PKey.read solves this begin/rescue garbage but is only
            # available to Ruby 1.9.3+ and may not solve the EC portion
            begin
                public_key = OpenSSL::PKey::RSA.new(data, password)
            rescue OpenSSL::PKey::RSAError
                begin
                    public_key = OpenSSL::PKey::DSA.new(data, password)
                rescue
                    begin
                        public_key = OpenSSL::PKey::EC.new(data, password)
                    rescue
                        raise ArgumentError, "Failed to load public key"
                    end
                end
            end

            if public_key.is_a?(OpenSSL::PKey::RSA)
                alg = "RSA"
                err = public_key.private?
            elsif public_key.is_a?(OpenSSL::PKey::DSA)
                alg = "DSA"
                err = public_key.private?
            elsif public_key.is_a?(OpenSSL::PKey::EC)
                alg = "EC"
                err = !public_key.public_key? || public_key.private_key?
            else
                raise R509::R509Error, "Unsupported algorithm for public key"
            end

            log.info "Algorithm=#{alg}, pem=#{public_key.to_pem}"
            if err
                raise R509::R509Error, "Not valid public key"
            end

            public_key
        end

        def generate_key(params)
            type = KEYTYPE_DEF
            bit_length = KEYLEN_DEF
            curve_name = ECCURVE_DEF

            if params.is_a?(Hash)
                if params.has_key?("type")
                    type = params["type"]
                end
                if params.has_key?("bit_length")
                    bit_length = params["bit_length"].to_i
                end
                if params.has_key?("curve_name")
                    curve_name = params["curve_name"]
                end
            end

            log.info "Generate private key (type=#{type}, " +
                "bit_length=#{bit_length}, curve_name=#{curve_name})"
            key = R509::PrivateKey.new(:type => type, :bit_length => bit_length,
                :curve_name => curve_name)

            key
        end

        #def generate_sans()
        #end

        def generate_request(request_raw, params)
            subject = subject_parser.parse(request_raw, "subject")
            if subject.empty?
                raise ArgumentError, "Must provide a subject"
            end

            if params.has_key?("public_key")
                public_key = load_public_key(
                    :public_key => params["public_key"])
            else
                raise ArgumentError, "Must provide a public key"
            end

            log.info "Generate CSR (subject=#{subject.to_s})"

            csr = csr_factory.build(:subject => subject,
                :public_key => public_key)
            csr
        end

        def sign_request(request_raw, params)
            if params.has_key?("csr")
                csr = params["csr"]
            else
                raise ArgumentError, "Must provide a CSR"
            end

            if params.has_key?("key")
                key = params["key"]
            else
                raise ArgumentError, "Must provide a private key"
            end

            log.info "Sign CSR (#{csr})"
            signed_csr = csr_factory.build(:csr => csr, :key => key,
                :message_digest => MESSAGE_DIGEST)

            signed_csr
        end

        def generate_signed_request(request_raw, params)
            subject = subject_parser.parse(request_raw, "subject")
            if subject.empty?
                raise ArgumentError, "Must provide a subject"
            end

            emit_key = 0
            if params.has_key?("key") && params.has_key?("newkey")
                raise ArgumentError, "Must provide a private key or the " +
                    "newkey option, not both"
            end
            if params.has_key?("key")
                key = R509::PrivateKey.new(:key => params["key"])
            elsif params.has_key?("newkey")
                emit_key = 1
                key = generate_key(params["newkey"])
            else
                raise ArgumentError, "Must provide a private key or the " +
                    "newkey option"
            end

            log.info "Generate signed CSR (subject=#{subject.to_s})"
            csr = csr_factory.build(:subject => subject,
                :san_names => generate_sans(),
                :key => key, :message_digest => MESSAGE_DIGEST)

            if emit_key == 1
                resp = { :csr => csr, :privatekey => key }
            else
                resp = { :csr => csr }
            end

            resp
        end

        def list_request_extensions(csr)
            # R509 non inserisce le estensioni della richiesta tra le estensioni
            # del certificato:
            # Estraggo le estensioni subjectAltName dalla richiesta per
            # poterle inserire manualmente nel certificato.
            extReq = []
            csr.req.attributes.each do |attribute|
                if attribute.oid == "extReq"
                    set = OpenSSL::ASN1.decode attribute.value
                    ext = set.value[0].value.map { |asn1ext|
                        OpenSSL::X509::Extension.new(asn1ext)
                    }
r509_ext = R509::Cert::Extensions.wrap_openssl_extensions(ext)
unless r509_ext[R509::Cert::Extensions::SubjectAlternativeName].nil?
    san = r509_ext[R509::Cert::Extensions::SubjectAlternativeName]
    extReq.push(san)
end
                    break
                end
            end

            extReq
        end
      end
    end
  end
end
