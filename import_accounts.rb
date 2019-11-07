require 'roo'
require 'roo-xls'

require 'spaceship'
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