require 'fileshunter/SegmentsAnalyzer'

module FilesHunter

  # Get a SegmentsAnalyzer that can be used to decode files.
  #
  # Parameters::
  # * *options* (<em>map<Symbol,Object></em>): Options given to the SegmentsAnalyzer. See its documentation to know possible options. [default = {}]
  def self.get_segments_analyzer(options = {})
    return ::FilesHunter::SegmentsAnalyzer.new(options)
  end

end
