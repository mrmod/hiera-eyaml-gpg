require 'gpgme'
require 'base64'
require 'pathname'
require 'hiera/backend/eyaml/encryptor'
require 'hiera/backend/eyaml/utils'
require 'hiera/backend/eyaml/options'

class Hiera
  module Backend
    module Eyaml
      module Encryptors

        class Gpg < Encryptor
          # Default recipient filename
          RCP_FILE = 'hiera-eyaml-gpg.recipient'
          self.tag = "GPG"

          self.options = {
            :gnupghome => { :desc => "Location of your GNUPGHOME directory",
                            :type => :string,
                            :default => ENV['GPGHOME'] || ENV['HOME'] + '/.gnupg', }
            :always_trust => { :desc => "Assume that used keys are fully trusted",
                               :type => :boolean,
                               :default => false },
            :recipients => { :desc => "List of recipients (comma separated)",
                             :type => :string },
            :recipients_file => { :desc => "File containing a list of recipients (one on each line)",
                             :type => :string }
          }

          def self.passfunc(hook, uid_hint, passphrase_info, prev_was_bad, fd)
            begin
                system('stty -echo')
                passphrase = ask("Enter passphrase for #{uid_hint}: ") { |q| q.echo = '*' }
                io = IO.for_fd(fd, 'w')
                io.puts(passphrase)
                io.flush
              ensure
                (0 ... $_.length).each do |i| $_[i] = ?0 end if $_
                  system('stty echo')
              end
              $stderr.puts
          end

          def self.find_recipients
            recipients = nil

            unless self.option(:recipients).nil?
              debug 'Using --recipients option'
              recipients = recipient_option.split ','
            else
              recipients = self.option :recipients_file
            end

            # Try to load recipients from the recipients-file option or a found file
            if recipients.nil?
              debug 'Searching for any hiera-eyaml-gpg.recipients files in the current path'
              debug "Inspecting Eyaml source: #{Eyaml::Options[:source].inspect}"
              filename = Eyaml::Options[
                  Eyaml::Options[:source]
              ]

              filename = Pathname.new(filename).realpath.dirname.descend do |dp|
                dp = dp.join(RCP_FILE)
                break dp if File.exist? dp
              end.to_s
              recipients = File.readlines.map(&:chomp).map(&:strip)
            end

            debug "Recipients: #{recipients.inspect}"

            recipients
          end

          def self.gnupghome
            ENV['GNUPGHOME'] = self.option :gnupghome)
            debug "GNUPGHOME redefined to #{ENV['GNUPGHOME']}"
          end

          def self.encrypt plaintext
            self.gnupghome
            ctx = GPGME::Ctx.new

            recipients = self.find_recipients
            debug("Recipents are #{recipients}")

            raise ArgumentError, 'No recipients provided, don\'t know who to encrypt to' if recipients.empty?

            keys = recipients.map {|r| ctx.keys(r).first }
            debug("Keys: #{keys}")

            always_trust = self.option(:always_trust)
            unless always_trust
              # check validity of recipients (this is possibly naive, but better than the unhelpful
              # error that it would spit out otherwise)
              keys.each do |key|
                unless key.primary_uid.validity >= GPGME::VALIDITY_FULL
                  raise StandardError, "Key #{key.sha} (#{key.email}) not trusted (if key trust is established by another means then specify always-trust)"
                end
              end
            end

            data = GPGME::Data.from_str(plaintext)
            crypto = GPGME::Crypto.new(:always_trust => always_trust)

            ciphertext = crypto.encrypt(data, :recipients => keys)
            ciphertext.seek 0
            ciphertext.read
          end

          def self.decrypt ciphertext
            self.gnupghome

            ctx = hiera? ? GPGME::Ctx.new : GPGME::Ctx.new(:passphrase_callback => method(:passfunc))


            unless ctx.keys.empty?
              raw = GPGME::Data.new(ciphertext)
              txt = GPGME::Data.new

              begin
                txt = ctx.decrypt(raw)
              rescue GPGME::Error::DecryptFailed => e
                warn("Fatal: Failed to decrypt ciphertext (check settings and that you are a recipient)")
                raise e
              rescue Exception => e
                warn("Warning: General exception decrypting GPG file")
                raise e
              end

              txt.seek 0
              txt.read
            else
              warn("No usable keys found in #{ENV['GNUPGHOME']}. Check :gpgpghome value in hiera.yaml is correct")
            end
          end

          def self.create_keys
            STDERR.puts "The GPG encryptor does not support creation of keys, use the GPG command lines tools instead"
          end

        end

      end
    end
  end
end