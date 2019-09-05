require 'spaceship'
require 'optparse'
require 'cert'
require 'pathname' 
require 'fastlane_core'
require 'fileutils'

 

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
    options[:bundle_id] = value
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
  options[:force] = true
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
  # Option 作为 flag，带一组用逗号分割的arguments，用于将arguments作为数组解析
  opts.on('-a A,B', '--array A,B', Array, 'List of arguments') do |value|
    options[:array] = value
  end
end.parse!

# puts options.inspect
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


 
puts "解锁钥匙串 : " + Time.now
default_keychain = `security default-keychain`
default_keychain_result = default_keychain.strip
`security unlock-keychain -p 123456  #{default_keychain_result}`
spaceship = Spaceship::Launcher.new(options[:username],options[:password])
filepath = Pathname.new(File.dirname(__FILE__)).realpath


 
puts "开始生成创建APP : " + Time.now
# Create a new app
companyname = options[:username].split('@').first

if options[:bundleid] == '' || options[:bundleid] == nil
    lastname = options[:username].split('@').first.reverse!
    options[:bundleid] = ['com',companyname,lastname].join('.')
    # puts options[:bundleid]
end
if options[:appname] == '' || options[:appname] == nil
    options[:appname] = options[:username].split('@').first.reverse!
    # puts options[:appname]
end
tmp_path = File.join(filepath,companyname)
FileUtils.mkdir_p(tmp_path) unless File.exists?(tmp_path)

cer_path = File.join(filepath,companyname,'certificate.cer')
profile_path = File.join(filepath,companyname,'embedded.mobileprovision')
app = spaceship.app.find(options[:bundleid])
unless app 

    app = spaceship.app.create!(bundle_id: options[:bundleid], name: options[:appname])
    
end
app.update_service(Spaceship::Portal.app_service.associated_domains.on)
app.update_service(Spaceship::Portal.app_service.push_notification.on)

 
puts "生成APP: " + Time.now

device = spaceship.device.find_by_udid(options[:udid], include_disabled: true)
# puts device
unless device
    #Register a new device
   unless options[:devicename]
       options[:devicename] = options[:udid]
   end
   begin
     device = spaceship.device.create!(name: options[:devicename], udid: options[:udid])
   rescue Exception => exception
     puts exception.message
     puts exception.backtrace.inspect
     exit
   end
end
device = device.enable!


puts "开始获取证书 : " + Time.now
cert_first= spaceship.certificate.development.all.first
if cert_first
    # puts cert
    File.write(cer_path,cert_first.download)
else
        # Create a new certificate signing request
    csr, pkey = spaceship.certificate.create_certificate_signing_request
    puts pkey
    # Use the signing request to create a new development certificate
    cert_first = spaceship.certificate.development.create!(csr: csr)
    # cert = Spaceship.certificate.development.all.first
    # puts cert
    File.write(cer_path,cert_first.download)
end

# origin fastlane cert
# `fastlane run cert development:true force:#{options[:force]} username:'#{options[:username]}' filename:'certificate.cer' output_path:'#{tmp_path}' keychain_password:'123456'`
puts "开始获取描述文件 : " + Time.now
cert = spaceship.certificate.development.all
# puts cert
profile_name = app.bundle_id + " #{Time.now.to_i}"
profile_dev = spaceship.provisioning_profile.development.create!(name:profile_name,bundle_id: app.bundle_id,
        certificate: cert)
# puts profile_dev
File.write(profile_path, profile_dev.download)
 
puts "当前时间 : " + Time.now

keychain_path = '/srv/www/Library/Keychains/login.keychain-db'
FastlaneCore::KeychainImporter.import_file(cer_path, keychain_path, keychain_password: '123456', certificate_password: '123456')

# origin fastlane import_certificate
# import_certificate_cmd = `fastlane run import_certificate certificate_path:"#{cer_path}" certificate_password:"123456" keychain_name:"login.keychain-db"`
#puts import_certificate_cmd
 
puts "开始重签 : " + Time.now
# pem_path = File.join(filepath,companyname,'certificate.pem')

resign_file_path = File.join(filepath,'wt_isign_macos.py')

# cer_to_pem = `openssl x509 -inform der -in #{cer_path} -out #{pem_path}`
# puts cer_to_pem
get_cer_subject_mobileprovision = `/usr/libexec/PlistBuddy -c 'Print DeveloperCertificates:0' /dev/stdin <<< $(security cms -D -i #{profile_path}) | openssl x509 -inform DER -noout -subject` 
# puts get_cer_subject_mobileprovision
sed_s = 's/\(.*\)\/CN=\(.*\)\/OU=\(.*\)/\2/g'
identity = `echo '#{get_cer_subject_mobileprovision}' | sed '#{sed_s}'`
# puts identity
codesign_identity = identity.strip
# profile.download

if options[:input] and options[:output]
# resign_cmd = "python #{resign_file_path} -i #{options[:input]} -d '#{codesign_identity}' -o #{options[:output]} -m #{profile_path}"
# puts resign_cmd
resign = `python #{resign_file_path} -i #{options[:input]} -d "#{codesign_identity}" -o #{options[:output]} -m #{profile_path}`
# puts resign
# Time.now 功能相同
puts "重签完成 : " + Time.now
if resign.include? "success"
  puts "success"
else
  puts "failure"
end

end