require 'spaceship'
require 'optparse'
require 'cert'
require 'pathname' 
require 'fastlane_core'
require 'fileutils'
require 'openssl'
require 'aliyun/oss'
require 'securerandom'
require 'match'


module Spaceship
  # rubocop:disable Metrics/ClassLength
  class Client
    def send_shared_login_request(user, password)
  # Check if we have a cached/valid session
  #
  # Background:
  # December 4th 2017 Apple introduced a rate limit - which is of course fine by itself -
  # but unfortunately also rate limits successful logins. If you call multiple tools in a
  # lane (e.g. call match 5 times), this would lock you out of the account for a while.
  # By loading existing sessions and checking if they're valid, we're sending less login requests.
  # More context on why this change was necessary https://github.com/fastlane/fastlane/pull/11108
  #
  # If there was a successful manual login before, we have a session on disk
    if load_session_from_file
    # Check if the session is still valid here
      begin
      # We use the olympus session to determine if the old session is still valid
      # As this will raise an exception if the old session has expired
      # If the old session is still valid, we don't have to do anything else in this method
      # that's why we return true
        return true if fetch_olympus_session
      rescue
      # If the `fetch_olympus_session` method raises an exception
      # we'll land here, and therefore continue doing a full login process
      # This happens if the session we loaded from the cache isn't valid any more
      # which is common, as the session automatically invalidates after x hours (we don't know x)
      # In this case we don't actually care about the exact exception, and why it was failing
      # because either way, we'll have to do a fresh login, where we do the actual error handling
      puts("Available session is not valid any more. Continuing with normal login.")
      end
    end
  #
  # The user can pass the session via environment variable (Mainly used in CI environments)
    if load_session_from_env
    # see above
      begin
      # see above
        return true if fetch_olympus_session
      rescue
        puts("Session loaded from environment variable is not valid. Continuing with normal login.")
      # see above
      end
    end
  #
  # After this point, we sure have no valid session any more and have to create a new one
  #

    data = {
      accountName: user,
      password: password,
      rememberMe: true
    }

    begin
    # The below workaround is only needed for 2 step verified machines
    # Due to escaping of cookie values we have a little workaround here
    # By default the cookie jar would generate the following header
    #   DES5c148...=HSARM.......xaA/O69Ws/CHfQ==SRVT
    # However we need the following
    #   DES5c148...="HSARM.......xaA/O69Ws/CHfQ==SRVT"
    # There is no way to get the cookie jar value with " around the value
    # so we manually modify the cookie (only this one) to be properly escaped
    # Afterwards we pass this value manually as a header
    # It's not enough to just modify @cookie, it needs to be done after self.cookie
    # as a string operation
      important_cookie = @cookie.store.entries.find { |a| a.name.include?("DES") }
      if important_cookie
        modified_cookie = self.cookie # returns a string of all cookies
        unescaped_important_cookie = "#{important_cookie.name}=#{important_cookie.value}"
        escaped_important_cookie = "#{important_cookie.name}=\"#{important_cookie.value}\""
        modified_cookie.gsub!(unescaped_important_cookie, escaped_important_cookie)
      end

      response = request(:post) do |req|
        req.url("https://idmsa.apple.com/appleauth/auth/signin")
        req.body = data.to_json
        req.headers['Content-Type'] = 'application/json'
        req.headers['X-Requested-With'] = 'XMLHttpRequest'
        req.headers['X-Apple-Widget-Key'] = self.itc_service_key
        req.headers['Accept'] = 'application/json, text/javascript'
        req.headers["Cookie"] = modified_cookie if modified_cookie
      end
    rescue UnauthorizedAccessError
      raise InvalidUserCredentialsError.new, "Invalid username and password combination. Used '#{user}' as the username."
    end

  # Now we know if the login is successful or if we need to do 2 factor

    case response.status
    when 403
      raise InvalidUserCredentialsError.new, "Invalid username and password combination. Used '#{user}' as the username."
    when 200
      fetch_olympus_session
      return response
    when 409
      fetch_olympus_session
      raise UnauthorizedAccessError.new, "Your cookie has expired, please log in again. Used '#{user}' as the username."

    else
      if (response.body || "").include?('invalid="true"')
      # User Credentials are wrong
        raise InvalidUserCredentialsError.new, "Invalid username and password combination. Used '#{user}' as the username."
      elsif response.status == 412 && AUTH_TYPES.include?(response.body["authType"])
      # Need to acknowledge Apple ID and Privacy statement - https://github.com/fastlane/fastlane/issues/12577
      # Looking for status of 412 might be enough but might be safer to keep looking only at what is being reported
        raise AppleIDAndPrivacyAcknowledgementNeeded.new, "Need to acknowledge to Apple's Apple ID and Privacy statement. Please manually log into https://appleid.apple.com (or https://appstoreconnect.apple.com) to acknowledge the statement."
      elsif (response['Set-Cookie'] || "").include?("itctx")
        raise "Looks like your Apple ID is not enabled for App Store Connect, make sure to be able to login online"
      else
        info = [response.body, response['Set-Cookie']]
        raise Tunes::Error.new, info.join("\n")
      end
    end
    end
  end
end

options = {}
option_parser = OptionParser.new do |opts|
  # 这里是这个命令行工具的帮助信息
  opts.banner = 'here is help messages of the command line tool.'

  #UDID
  opts.on('-d UDID','--udid UDID','Device UDID') do |value|
    options[:udid] = value
    if options[:udid] == '' || options[:udid] == nil
        puts 'Please Input UDID'
        exit
    end
  end 
  #Input
  options[:input] = '' 
  opts.on('-i INPUT','--input Input','Ipa Input Path') do |value|
    options[:input] = value
    if options[:input] == '' || options[:input] == nil
      puts 'Please Input Ipa Path'
      exit
    end
  end

  #Output
  
  options[:output] = '' 
  opts.on('-o OUTPUT','--output Output','Ipa Output Path') do |value|
    options[:output] = value
  end

  #BundleID
  opts.on('-b BUNDLEID','--bundleid BundleID','Pass-in Bundle Identifier') do |value|
    options[:bundle_id] = value.strip
  end

  #DisplayName
  opts.on('-D DISPLAYNAME','--displayname DisplayName','Pass-in DisplayName') do |value|
    options[:displayname] = value.strip
  end

  #Username
  options[:username] = 'ce24486@163.com'
  opts.on('-u USERNAME','--username Username','Apple ID') do |value|
    options[:username] = value
  end

  #Password
  options[:password] = '209523De1A'
  opts.on('-p PASSWORD','--password Password','Password Of Apple ID') do |value|
    options[:password] = value
  end
  #Force New Certificate
  options[:force] = false
  opts.on('-f FORCE','--force Force','Force New Certificate') do |value|
    options[:force] = value
  end
 

  # Option 作为 flag，带argument，用于将argument作为数值解析，比如"name"信息
  #下面的“value”就是用户使用时输入的argument
  opts.on('-n APPNAME', '--appname AppName', 'Pass-in App Name') do |value|
    options[:appname] = value
  end
#  options[:devicename] = 'Default Phone'
  opts.on('-N DEVICENAME','--devicename DeviceName','Pass-in Device Name') do |value|
    options[:devicename] = value
  end
  options[:development] = true
  opts.on('-t DEVELOPMENT','--development Development','Certificate Type/Resign Type') do |value|
    options[:development] = value
  end
  # Option 作为 flag，带一组用逗号分割的arguments，用于将arguments作为数组解析
  opts.on('-a A,B', '--array A,B', Array, 'List of arguments') do |value|
    options[:array] = value
  end
end.parse!

puts options.inspect
# if options[:username]



if options[:input] == '' || options[:input] == nil
  puts 'Please Input Ipa Path'
  exit
end
if options[:udid] == '' || options[:udid] == nil
    puts 'Please Input UDID'
    exit
end
# Create default output path
if options[:output] == '' || options[:output] == nil
    puts 'Please Output Ipa Path'
    exit
end

UDID = options[:udid]
 
puts "解锁钥匙串 : " + " #{Time.now}"
default_keychain = `security default-keychain`
default_keychain_result = default_keychain.strip
`security unlock-keychain -p V@kP4eLnUU5l #{default_keychain_result}`
user_name = options[:username]
puts user_name
spaceship = nil 
begin
  spaceship = Spaceship::Launcher.new(user_name,options[:password])

rescue => exception
  puts user_name
  puts exception.class
  exit
end


filepath = Pathname.new(File.dirname(__FILE__)).realpath


 
puts "开始生成创建APP : " + " #{Time.now}"
# Create a new app
companyname = user_name.split('@').first
lastname = SecureRandom.hex(10)
default_bundle_id = ['com',companyname,lastname].join('.')
#if options[:bundleid] == '' || options[:bundleid] == nil
#    options[:bundleid] = default_bundle_id
#end
if options[:appname] == '' || options[:appname] == nil
    options[:appname] = user_name.split('@').first.reverse!
    # puts options[:appname]
end
tmp_path = File.join(filepath,companyname,UDID)
FileUtils.mkdir_p(tmp_path) unless File.exists?(tmp_path)


# companyname_tmp_path = File.join(filepath,companyname)

# cer_p12_path = File.join(filepath,companyname,'certificate.p12')
app = nil
begin
  app = spaceship.app.find(default_bundle_id)

rescue => exception
  # legacy support
  # BasicPreferredInfoError = Spaceship::BasicPreferredInfoError
  # InvalidUserCredentialsError = Spaceship::InvalidUserCredentialsError
  # NoUserCredentialsError = Spaceship::NoUserCredentialsError
  # ProgramLicenseAgreementUpdated = Spaceship::ProgramLicenseAgreementUpdated
  # InsufficientPermissions = Spaceship::InsufficientPermissions
  # UnexpectedResponse = Spaceship::UnexpectedResponse
  # AppleTimeoutError = Spaceship::AppleTimeoutError
  # UnauthorizedAccessError = Spaceship::UnauthorizedAccessError
  # GatewayTimeoutError = Spaceship::GatewayTimeoutError
  # InternalServerError = Spaceship::InternalServerError
  # BadGatewayError = Spaceship::BadGatewayError
  puts exception.message
  puts user_name
  puts exception.class

  exit

end
unless app 
    app = spaceship.app.create!(bundle_id: default_bundle_id, name: options[:appname])
    app.update_service(Spaceship::Portal.app_service.associated_domains.on)
    app.update_service(Spaceship::Portal.app_service.push_notification.on)
end


 
puts "生成APP: " + " #{Time.now}"

device = spaceship.device.find_by_udid(UDID, include_disabled: true)
# puts device
unless device
    #Register a new device
   unless options[:devicename]
       options[:devicename] = UDID
   end
   begin
     device = spaceship.device.create!(name: options[:devicename], udid: UDID)
   rescue Exception => exception
      
      if exception.message.include? "deviceNumber"
        puts UDID
        puts user_name
        puts "Spaceship::InvalidUDIDError"
        
        
      elsif exception.message.include? "maximum number"
        puts UDID
        puts exception.message
        puts user_name
        puts "Spaceship::MaxUDIDsError"
      
      elsif exception.message.include? "error"
        puts UDID
        puts exception.message
        puts user_name
        puts "Spaceship::OtherUDIDError"
      else 
        puts exception.message
      end
      exit
   end
end
device = device.enable!


puts "开始获取证书 : " + " #{Time.now}"
  
if options[:development] == true
  cer_path = File.join(filepath,companyname,'certificate.cer')
  profile_path = File.join(tmp_path,'embedded.mobileprovision')
  private_key_path = File.join(filepath,companyname,'key.p12')
  cert = spaceship.certificate.development.all
  if cert.count == 0 || options[:force] == true || File.exists?(cer_path) == false || File.exists?(private_key_path) == false
    puts "登录oss"

    client = Aliyun::OSS::Client.new(
    :endpoint => 'https://oss-cn-hongkong.aliyuncs.com',
    :access_key_id => 'LTAIe2W3EwkUiV02',
    :access_key_secret => '5rQbdIkSEsrIpZdf0WFAySdTQ0jJG3')
    bucket = client.get_bucket('apps-new2')
    key1 = "certificate_and_keys/#{companyname}/key.p12"
    key2 = "certificate_and_keys/#{companyname}/certificate.cer"

    if bucket.object_exists?(key1) == true && bucket.object_exists?(key2) == true && cert.count != 0
      puts "oss下载证书"
      bucket.get_object(key1, :file => private_key_path)
      bucket.get_object(key2, :file => cer_path)


    else
      if cert.count >= 2
        revoke_count = 0
        cert.each do |certificate|
          begin
            puts "#{certificate.id} #{certificate.name} has expired, revoking..." 
            certificate.revoke!
            revoke_count += 1
          rescue => e
            puts "An error occurred while revoking #{certificate.id} #{certificate.name}" 
            puts "#{e.message}\n#{e.backtrace.join("\n")}" if FastlaneCore::Globals.verbose?
            
          end
        end
        puts "#{revoke_count} expired certificate#{'s' if revoke_count != 1} #{revoke_count == 1 ? 'has' : 'have'} been revoked! 👍" if FastlaneCore::Globals.verbose?

      end
      puts "创建证书"
      csr, pkey = spaceship.certificate.create_certificate_signing_request
      File.write(private_key_path,pkey)
      # Use the signing request to create a new development certificate
      cert_first = spaceship.certificate.development.create!(csr: csr)
      # cert = Spaceship.certificate.development.all.first
      # puts cert
      File.write(cer_path,cert_first.download)
      puts "oss上传证书"
      bucket.put_object(key1,:file => private_key_path)
      bucket.put_object(key2,:file => cer_path)
    end
    puts "导入keychain证书"
    installed = false
    begin
      installed = FastlaneCore::CertChecker.installed?(cer_path, in_keychain: '/srv/www/Library/Keychains/login.keychain-db')

    rescue => exception
      puts "Platform::CertCheckerError"
      installed = false
      
    end 
    if installed == true
    
    else
      begin
        FastlaneCore::KeychainImporter.import_file(private_key_path, '/srv/www/Library/Keychains/login.keychain-db', keychain_password: 'V@kP4eLnUU5l')
        FastlaneCore::KeychainImporter.import_file(cer_path, '/srv/www/Library/Keychains/login.keychain-db', keychain_password: 'V@kP4eLnUU5l')
      rescue => exception
        puts "Platform::KeychainImporterError"
        exit

      end
      
    end

  

  end


  # origin fastlane cert
  # `fastlane run cert development:true force:#{options[:force]} username:'#{options[:username]}' filename:'certificate.cer' output_path:'#{tmp_path}' keychain_password:'123456'`
  puts "开始获取描述文件 : " + " #{Time.now}"
  cert = spaceship.certificate.development.all

  # puts cert
  profile_name = app.bundle_id + " #{SecureRandom.uuid}"
  begin
    profile_dev = spaceship.provisioning_profile.development.create!(name:profile_name,bundle_id: app.bundle_id,
      certificate: cert)
    # puts profile_dev
    File.write(profile_path, profile_dev.download)
  rescue => exception
    puts "Spaceship::CreateProfileError"
    exit
  end
  
 


  # origin fastlane import_certificate
  # import_certificate_cmd = `fastlane run import_certificate certificate_path:"#{cer_path}" certificate_password:"123456" keychain_name:"login.keychain-db"`
  #puts import_certificate_cmd
 

  # pem_path = File.join(filepath,companyname,'certificate.pem')
  puts "复制mobileprovision到对应文件夹 : " + " #{Time.now}"
  resign_file_path = File.join(filepath,'wt_isign_macos.py')
  tmp_resign_file_path = File.join(tmp_path,'wt_isign_macos.py')
  FileUtils.cp resign_file_path,tmp_path 
  # cer_to_pem = `openssl x509 -inform der -in #{cer_path} -out #{pem_path}`
  # puts cer_to_pem
  puts "获取mobileprovision里面的sign_identity : " + " #{Time.now}"

  get_cer_subject_mobileprovision = `/usr/libexec/PlistBuddy -c 'Print DeveloperCertificates:0' /dev/stdin <<< $(security cms -D -i #{profile_path}) | openssl x509 -inform DER -noout -subject` 
  # puts get_cer_subject_mobileprovision
  sed_s = 's/\(.*\)\/CN=\(.*\)\/OU=\(.*\)/\2/g'
  identity = `echo '#{get_cer_subject_mobileprovision}' | sed '#{sed_s}'`
  # puts identity
  codesign_identity = identity.strip
  # profile.download
  output_path = options[:output]
  input_path = options[:input]
  puts "输入#{input_path}"
  if input_path and output_path
    puts "创建输出目录 : " + " #{Time.now}"
    out_dir = File.dirname(output_path)
    # puts out_dir
    FileUtils.mkdir_p(out_dir) unless File.exists?(out_dir)

    puts "开始重签 : " + " #{Time.now}"
      if options[:bundleid] == nil || options[:bundleid] == ''
        if options[:displayname] == nil || options[:displayname] == ''
          resign = `python #{tmp_resign_file_path} -i #{input_path} -d "#{codesign_identity}" -o #{output_path} -m #{profile_path}`
          # puts resign
          # " #{Time.now}" 功能相同
          puts "重签完成 : " + " #{Time.now}"
          if resign.include? "success"
            puts "success"
          else
                if resign.include? "IOError" or resign.include? "zipfile"
                puts "Platform::ZipError"
                else
                puts "Platform::ResignError"
                end
          end
          exit
        else
          resign = `python #{tmp_resign_file_path} -i #{input_path} -d "#{codesign_identity}" -o #{output_path} -m #{profile_path} -n "#{options[:displayname]}"`
          # puts resign
          # " #{Time.now}" 功能相同
          puts "重签完成 : " + " #{Time.now}"
          if resign.include? "success"
            puts "success"
          else
                if resign.include? "IOError" or resign.include? "zipfile"
                puts "Platform::ZipError"
                else
                puts "Platform::ResignError"
                end
          end
          exit
        end
      else
        if options[:displayname] == nil || options[:displayname] == ''
          resign = `python #{tmp_resign_file_path} -i #{input_path} -d "#{codesign_identity}" -o #{output_path} -m #{profile_path} -b "#{options[:bundleid]}"`
          # puts resign
          # " #{Time.now}" 功能相同
          puts "重签完成 : " + " #{Time.now}"
          if resign.include? "success"
            puts "success"
          else
                if resign.include? "IOError" or resign.include? "zipfile"
                puts "Platform::ZipError"
                else
                puts "Platform::ResignError"
                end
          end
          exit
        else
          resign = `python #{tmp_resign_file_path} -i #{input_path} -d "#{codesign_identity}" -o #{output_path} -m #{profile_path} -b "#{options[:bundleid]}" -n "#{options[:displayname]}"`
          # puts resign
          # " #{Time.now}" 功能相同
          puts "重签完成 : " + " #{Time.now}"
          if resign.include? "success"
            puts "success"
          else
                if resign.include? "IOError" or resign.include? "zipfile"
                puts "Platform::ZipError"
                else
                puts "Platform::ResignError"
                end
          end
          exit
        end
        
      end
  end
else
  cer_path = File.join(filepath,companyname,'certificate_production.cer')
  profile_path = File.join(tmp_path,'embedded.mobileprovision')
  private_key_path = File.join(filepath,companyname,'key_production.p12')
  cert_id_path = File.join(filepath,companyname,"cert_id_production.txt")
  cert = spaceship.certificate.production.all
  if cert.count == 0 || options[:force] == true || File.exists?(cer_path) == false || File.exists?(private_key_path) == false || File.exists?(cert_id_path) == false
    puts "登录oss"
    client = Aliyun::OSS::Client.new(
    :endpoint => 'https://oss-cn-hongkong.aliyuncs.com',
    :access_key_id => 'LTAIe2W3EwkUiV02',
    :access_key_secret => '5rQbdIkSEsrIpZdf0WFAySdTQ0jJG3')
    bucket = client.get_bucket('apps-new2')
    key1 = "certificate_and_keys/#{companyname}/key_production.p12"
    key2 = "certificate_and_keys/#{companyname}/certificate_production.cer"
    key3 = "certificate_and_keys/#{companyname}/cert_id_production.txt"
    
    if bucket.object_exists?(key1) == true && bucket.object_exists?(key2) == true && bucket.object_exists?(key3) == true && cert.count != 0
      puts "oss下载证书"
      bucket.get_object(key1, :file => private_key_path)
      bucket.get_object(key2, :file => cer_path)
      bucket.get_object(key3, :file => cert_id_path)
      a_cert_id = File.read(cert_id_path)
    else
      if cert.count >= 1
        revoke_count = 0
        cert.each do |certificate|
          begin
            puts "#{certificate.id} #{certificate.name} has expired, revoking..." 
            certificate.revoke!
            revoke_count += 1
          rescue => e
            puts "An error occurred while revoking #{certificate.id} #{certificate.name}" 
            puts "#{e.message}\n#{e.backtrace.join("\n")}" if FastlaneCore::Globals.verbose?
            
          end
        end
        puts "#{revoke_count} expired certificate#{'s' if revoke_count != 1} #{revoke_count == 1 ? 'has' : 'have'} been revoked! 👍" if FastlaneCore::Globals.verbose?

      end
      puts "oss创建证书"
      csr, pkey = spaceship.certificate.create_certificate_signing_request
      File.write(private_key_path,pkey)
      # Use the signing request to create a new development certificate
      a = spaceship.certificate.production.create!(csr: csr)
      # cert = Spaceship.certificate.development.all.first
      # puts cert
      File.write(cer_path,a.download)
      File.write(cert_id_path,a.id)
      a_cert_id = a.id
      puts "上传证书"
      bucket.put_object(key1,:file => private_key_path)
      bucket.put_object(key2,:file => cer_path)
      bucket.put_object(key3,:file => cert_id_path)
    end
    puts "导入keychain证书"
    installed = false
    begin
      installed = FastlaneCore::CertChecker.installed?(cer_path, in_keychain: '/srv/www/Library/Keychains/login.keychain-db')

    rescue => exception
      puts "Platform::CertCheckerError"
      installed = false
      
    end 
    if installed == true
    
    else
      begin
        FastlaneCore::KeychainImporter.import_file(private_key_path, '/srv/www/Library/Keychains/login.keychain-db', keychain_password: 'V@kP4eLnUU5l')
        FastlaneCore::KeychainImporter.import_file(cer_path, '/srv/www/Library/Keychains/login.keychain-db', keychain_password: 'V@kP4eLnUU5l')
      rescue => exception
        puts "Platform::KeychainImporterError"
        exit

      end
      
    end

  end
  a_cert_id = File.read(cert_id_path)
  puts a_cert_id
  a_cert = spaceship.certificate.production.find(a_cert_id, mac: false)
 

  # origin fastlane cert
  # `fastlane run cert development:true force:#{options[:force]} username:'#{options[:username]}' filename:'certificate.cer' output_path:'#{tmp_path}' keychain_password:'123456'`
  puts "开始获取描述文件 : " + " #{Time.now}"
  # a_cert = spaceship.certificate.production.all.first

  # puts cert
  profile_name = app.bundle_id + " #{SecureRandom.uuid}"
  begin
    profile_dev = spaceship.provisioning_profile.ad_hoc.create!(name:profile_name,bundle_id: app.bundle_id,
      certificate: a_cert)
    # puts profile_dev
    File.write(profile_path, profile_dev.download)
  rescue => exception
    puts "Spaceship::CreateProfileError"
    exit
  end
  
 


  # origin fastlane import_certificate
  # import_certificate_cmd = `fastlane run import_certificate certificate_path:"#{cer_path}" certificate_password:"123456" keychain_name:"login.keychain-db"`
  #puts import_certificate_cmd
 

  # pem_path = File.join(filepath,companyname,'certificate.pem')
  puts "复制mobileprovision到对应文件夹 : " + " #{Time.now}"
  resign_file_path = File.join(filepath,'wt_isign_macos.py')
  tmp_resign_file_path = File.join(tmp_path,'wt_isign_macos.py')
  FileUtils.cp resign_file_path,tmp_path unless File.exists?(tmp_resign_file_path)
  # cer_to_pem = `openssl x509 -inform der -in #{cer_path} -out #{pem_path}`
  # puts cer_to_pem
  puts "获取mobileprovision里面的sign_identity : " + " #{Time.now}"

  get_cer_subject_mobileprovision = `/usr/libexec/PlistBuddy -c 'Print DeveloperCertificates:0' /dev/stdin <<< $(security cms -D -i #{profile_path}) | openssl x509 -inform DER -noout -subject` 
  # puts get_cer_subject_mobileprovision
  sed_s = 's/\(.*\)\/CN=\(.*\)\/OU=\(.*\)/\2/g'
  # identity = `echo '#{get_cer_subject_mobileprovision}' | sed '#{sed_s}'`
  # puts identity
  puts Match::Utils.get_cert_info(cer_path)
  # identity = nil
  # begin
  #   identity = Match::Utils.get_cert_info(cer_path)[1][1]
  # rescue => exception
  identity = `echo '#{get_cer_subject_mobileprovision}' | sed '#{sed_s}'`

  # end

  codesign_identity = identity.strip
  # profile.download
  output_path = options[:output]
  input_path = options[:input]
  puts "输入#{input_path}"
  if input_path and output_path
  
    puts "创建输出目录 : " + " #{Time.now}"
    out_dir = File.dirname(output_path)
    # puts out_dir
    FileUtils.mkdir_p(out_dir) unless File.exists?(out_dir)

    puts "开始重签 : " + " #{Time.now}"
      if options[:bundleid] == nil || options[:bundleid] == ''
        if options[:displayname] == nil || options[:displayname] == ''
          resign = `python #{tmp_resign_file_path} -i #{input_path} -d "#{codesign_identity}" -o #{output_path} -m #{profile_path}`
          # puts resign
          # " #{Time.now}" 功能相同
          puts "重签完成 : " + " #{Time.now}"
          if resign.include? "success"
          puts "success"
          else
              if resign.include? "IOError" or resign.include? "zipfile"
              puts "Platform::ZipError"
              else
              puts "Platform::ResignError"
              end
          end
          exit
        else
          resign = `python #{tmp_resign_file_path} -i #{input_path} -d "#{codesign_identity}" -o #{output_path} -m #{profile_path} -n "#{options[:displayname]}"`
          # puts resign
          # " #{Time.now}" 功能相同
          puts "重签完成 : " + " #{Time.now}"
          if resign.include? "success"
          puts "success"
          else
              if resign.include? "IOError" or resign.include? "zipfile"
              puts "Platform::ZipError"
              else
              puts "Platform::ResignError"
              end
          end
          exit
        end
        
      else
        if options[:displayname] == nil || options[:displayname] == ''
          resign = `python #{tmp_resign_file_path} -i #{input_path} -d "#{codesign_identity}" -o #{output_path} -m #{profile_path} -b "#{options[:bundleid]}"`
          # puts resign
          # " #{Time.now}" 功能相同
          puts "重签完成 : " + " #{Time.now}"
          if resign.include? "success"
          puts "success"
          else
              if resign.include? "IOError" or resign.include? "zipfile"
              puts "Platform::ZipError"
              else
              puts "Platform::ResignError"
              end
          end
          exit
        else
          resign = `python #{tmp_resign_file_path} -i #{input_path} -d "#{codesign_identity}" -o #{output_path} -m #{profile_path} -b "#{options[:bundleid]}" -n "#{options[:displayname]}"`
          # puts resign
          # " #{Time.now}" 功能相同
          puts "重签完成 : " + " #{Time.now}"
          if resign.include? "success"
          puts "success"
          else
            if resign.include? "IOError" or resign.include? "zipfile"
            puts "Platform::ZipError"
            else
            puts "Platform::ResignError"
            end
          end
          exit
        end
      end
  end
end
  

  



