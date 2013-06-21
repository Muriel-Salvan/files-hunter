root_dir = File.expand_path(Dir.getwd)
Dir.glob("#{root_dir}/ext/**/extconf.rb").each do |extconf_path|
  puts "===== Building #{extconf_path} ..."
  Dir.chdir(File.dirname(extconf_path))
  if (!system('ruby -w extconf.rb'))
    raise RuntimeError.new("Error while generating Makefile #{extconf_path}: #{$?}")
  end
  if (!system('make'))
    raise RuntimeError.new("Error while building #{extconf_path}: #{$?}")
  end
  Dir.chdir(root_dir)
  puts "===== #{extconf_path} built ok."
  puts ''
end
