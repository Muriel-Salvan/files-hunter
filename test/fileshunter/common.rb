require 'tmpdir'
require 'fileutils'

module FilesHunterTest

  module Common

    FILES_ROOT_PATH = "#{File.dirname(__FILE__)}/files/sane"

    @@segments_analyzer = nil
    def segments_analyzer
      @@segments_analyzer = FilesHunter::get_segments_analyzer if (@@segments_analyzer == nil)
      return @@segments_analyzer
    end

    # Cache of segments, per file name
    @@segments_cache = {}
    # Return a cached version of segments for a given file
    #
    # Parameters::
    # * *file_name* (_String_): The file name to find segments for
    # Result::
    # * <em>list<Segment></em>: Its corresponding list of segments
    def get_cached_segments(file_name)
      @@segments_cache[file_name] = segments_analyzer.get_segments(file_name) if (@@segments_cache[file_name] == nil)

      return @@segments_cache[file_name]
    end


    # Get a temporary file name from an existing one, keeping its extension
    #
    # Parameters::
    # * *file_name* (_String_): Original file name
    # * _Block_: Block called with the temporary file name:
    #   * Parameters::
    #   * *temp_file_name* (_String_): Temporary file name
    def prepare_temp_file(file_name)
      temp_file_name = "#{Dir.tmpdir}/FilesHunterTest/#{File.basename(file_name)}"
      FileUtils::mkdir_p(File.dirname(temp_file_name))
      yield(temp_file_name)
    end

  end

end
