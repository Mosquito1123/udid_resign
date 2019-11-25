require 'roo'
require 'roo-xls'
require 'spaceship'
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
xlsx = Roo::Spreadsheet.open('./accounts.xls')
puts xlsx.info
a = xlsx.sheets.first
b = xlsx.sheet(a)
puts b.class
default_keychain = `security default-keychain`
default_keychain_result = default_keychain.strip
`security unlock-keychain -p V@kP4eLnUU5l #{default_keychain_result}`

# b.each_row({offset: 2}) do |row| # Will exclude first (inevitably header) row
#     puts row.inspect # Array of Excelx::Cell objects
# end
b.each(username: "邮箱", password: "ID 密码") do |hash|
    username = hash[:username].to_s
    password = hash[:password].to_s
    if username == '邮箱' || password == 'ID 密码' || username == nil || password == nil
    else
        spaceship = nil 
        begin
            spaceship = Spaceship::Launcher.new(username.to_s,password.to_s)

        rescue => exception
            
            puts exception.class
        end
    end
        
    # => { id: 1, name: 'John Smith' }
end