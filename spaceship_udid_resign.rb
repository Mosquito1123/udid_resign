require 'spaceship'
require 'optparse'
require 'cert'
require 'pathname' 
time1 = Time.new
 
puts "当前时间 : " + time1.inspect
 

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

timea = Time.new
 
puts "解锁钥匙串 : " + timea.inspect
default_keychain = `security default-keychain`
default_keychain_result = default_keychain.strip
`security unlock-keychain -p 123456  #{default_keychain_result}`
Spaceship.login(options[:username],options[:password])
filepath = Pathname.new(File.dirname(__FILE__)).realpath

tmp_path = File.join(filepath,'tmp')
cer_path = File.join(filepath,'tmp','certificate.cer')
profile_path = File.join(filepath,'tmp','embedded.mobileprovision')
timeb = Time.new
 
puts "开始生成创建APP : " + timeb.inspect
# Create a new app

if options[:bundleid] == '' || options[:bundleid] == nil
    companyname = options[:username].split('@').first
    lastname = options[:username].split('@').first.reverse!
    options[:bundleid] = ['com',companyname,lastname].join('.')
    # puts options[:bundleid]
end
if options[:appname] == '' || options[:appname] == nil
    options[:appname] = options[:username].split('@').first.reverse!
    # puts options[:appname]
end

app = Spaceship::Portal.app.find(options[:bundleid])
unless app 

    app = Spaceship.app.create!(bundle_id: options[:bundleid], name: options[:appname])
    
end
app.update_service(Spaceship::Portal.app_service.associated_domains.on)
app.update_service(Spaceship::Portal.app_service.push_notification.on)

timec = Time.new
 
puts "生成APP: " + timec.inspect

device = Spaceship.device.find_by_udid(options[:udid], include_disabled: true)
device = device.enable!
puts device
unless device
    #Register a new device
   unless options[:devicename]
       options[:devicename] = options[:udid]
   end
   begin
     device = Spaceship.device.create!(name: options[:devicename], udid: options[:udid])
     device.enable!
   rescue Exception => exception
     puts exception.message
     puts exception.backtrace.inspect
     exit
   end
end
timee = Time.new

puts "开始获取证书 : " + timee.inspect
cert_cmd = `fastlane run cert development:true force:#{options[:force]} username:'#{options[:username]}' filename:'certificate.cer' output_path:'#{tmp_path}' keychain_password:'123456'`
puts cert_cmd
timef = Time.new
puts "开始获取描述文件 : " + timef.inspect
cert = Spaceship.certificate.development.all
puts cert
profile_path = File.join(filepath,'tmp','embedded.mobileprovision')
profile_dev = Spaceship.provisioning_profile.development.create!(bundle_id: app.bundle_id,
        certificate: cert)
puts profile_dev
File.write(profile_path, profile_dev.download)
timeg = Time.new
 
puts "当前时间 : " + timeg.inspect
import_certificate_cmd = `fastlane run import_certificate certificate_path:"#{cer_path}" certificate_password:"123456" keychain_name:"login.keychain-db"`
#puts import_certificate_cmd
timeh = Time.new
 
puts "开始重签 : " + timeh.inspect
pem_path = File.join(filepath,'tmp','certificate.pem')

resign_file_path = File.join(filepath,'wt_isign_macos.py')

cer_to_pem = `openssl x509 -inform der -in #{cer_path} -out #{pem_path}`
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
time2 = Time.now
puts "重签完成 : " + time2.inspect
if resign.include? "success"
  puts "success"
else
  puts "failure"
end

end