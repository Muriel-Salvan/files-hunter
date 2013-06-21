module FilesHunterTest

  module Common

    FILES_ROOT_PATH = "#{File.dirname(__FILE__)}/files/sane"

    @@segments_analyzer = nil
    def segments_analyzer
      @@segments_analyzer = FilesHunter::get_segments_analyzer if (@@segments_analyzer == nil)
      return @@segments_analyzer
    end

  end

end
