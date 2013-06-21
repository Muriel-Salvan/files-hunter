RubyPackager::ReleaseInfo.new.
  author(
    :name => 'Muriel Salvan',
    :email => 'muriel@x-aeon.com',
    :web_page_url => 'http://murielsalvan.users.sourceforge.net'
  ).
  project(
    :name => 'Files Hunter',
    :web_page_url => 'https://github.com/Muriel-Salvan/files-hunter',
    :summary => 'Analyze files to get their real format. Ideal to retrieve hidden and corrupted files.',
    :description => 'Analyze files and guess their true content\'s format. Extract hidden files from corrupted ones. Easily extensible by adding new plug-ins for new formats. Handles documents, videos, images, music, executables...',
    :image_url => 'http://fileshunter.sourceforge.net/wiki/images/c/c9/Logo.png',
    :favicon_url => 'http://fileshunter.sourceforge.net/wiki/images/2/26/Favicon.png',
    :browse_source_url => 'https://github.com/Muriel-Salvan/files-hunter',
    :dev_status => 'Beta'
  ).
  add_core_files( [
    '{lib,bin}/**/*',
    '{ext,external}/**/*.{rb,c,h}'
  ] ).
  add_test_files( [
    'test/**/*'
  ] ).
  add_additional_files( [
    'README',
    'README.md',
    'LICENSE',
    'AUTHORS',
    'Credits',
    'ChangeLog',
    'Rakefile'
  ] ).
  gem(
    :gem_name => 'fileshunter',
    :gem_platform_class_name => 'Gem::Platform::RUBY',
    :require_paths => [ 'lib', 'ext' ],
    :has_rdoc => true,
    :test_file => 'test/run.rb',
    :gem_dependencies => [
      [ 'rUtilAnts', '>= 1.0' ],
      [ 'ioblockreader', '>= 1.0.3' ],
      [ 'bindata' ]
    ],
    :extensions => [
      'ext/fileshunter/Decoders/extconf.rb'
    ]
  ).
  source_forge(
    :login => 'murielsalvan',
    :project_unix_name => 'fileshunter',
    :ask_for_key_passphrase => true
  ).
  ruby_forge(
    :project_unix_name => 'files-hunter'
  )
