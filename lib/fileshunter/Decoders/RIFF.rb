# encoding: ASCII-8BIT

module FilesHunter

  module Decoders

    class RIFF < BeginPatternDecoder

      # Reference: http://www.sno.phy.queensu.ca/~phil/exiftool/TagNames/RIFF.html
      # Reference: http://msdn.microsoft.com/en-us/library/windows/desktop/dd318189%28v=vs.85%29.aspx
      # Reference: http://www.the-labs.com/Video/odmlff2-avidef.pdf

      BEGIN_PATTERN_RIFF = 'RIFF'
      BEGIN_PATTERN_RIFX = 'RIFX'
      BEGIN_PATTERN_JUNK = 'JUNK'
      BEGIN_PATTERN_FILE = Regexp.new("RIF(F|X)", nil, 'n')

      # INFO elements
      INFO_ELEMENTS_ID = {
        'AGES' => :Rated,
        'CMNT' => :Comment,
        'CODE' => :EncodedBy,
        'COMM' => :Comments,
        'DIRC' => :Directory,
        'DISP' => :SoundSchemeTitle,
        'DTIM' => :DateTimeOriginal,
        'GENR' => :Genre,
        'IARL' => :ArchivalLocation,
        'IART' => :Artist,
        'IAS1' => :FirstLanguage,
        'IAS2' => :SecondLanguage,
        'IAS3' => :ThirdLanguage,
        'IAS4' => :FourthLanguage,
        'IAS5' => :FifthLanguage,
        'IAS6' => :SixthLanguage,
        'IAS7' => :SeventhLanguage,
        'IAS8' => :EighthLanguage,
        'IAS9' => :NinthLanguage,
        'IBSU' => :BaseURL,
        'ICAS' => :DefaultAudioStream,
        'ICDS' => :CostumeDesigner,
        'ICMS' => :Commissioned,
        'ICMT' => :Comment,
        'ICNM' => :Cinematographer,
        'ICNT' => :Country,
        'ICOP' => :Copyright,
        'ICRD' => :DateCreated,
        'ICRP' => :Cropped,
        'IDIM' => :Dimensions,
        'IDPI' => :DotsPerInch,
        'IDST' => :DistributedBy,
        'IEDT' => :EditedBy,
        'IENC' => :EncodedBy,
        'IENG' => :Engineer,
        'IGNR' => :Genre,
        'IKEY' => :Keywords,
        'ILGT' => :Lightness,
        'ILGU' => :LogoURL,
        'ILIU' => :LogoIconURL,
        'ILNG' => :Language,
        'IMBI' => :MoreInfoBannerImage,
        'IMBU' => :MoreInfoBannerURL,
        'IMED' => :Medium,
        'IMIT' => :MoreInfoText,
        'IMIU' => :MoreInfoURL,
        'IMUS' => :MusicBy,
        'INAM' => :Title,
        'IPDS' => :ProductionDesigner,
        'IPLT' => :NumColors,
        'IPRD' => :Product,
        'IPRO' => :ProducedBy,
        'IRIP' => :RippedBy,
        'IRTD' => :Rating,
        'ISBJ' => :Subject,
        'ISFT' => :Software,
        'ISGN' => :SecondaryGenre,
        'ISHP' => :Sharpness,
        'ISRC' => :Source,
        'ISRF' => :SourceForm,
        'ISTD' => :ProductionStudio,
        'ISTR' => :Starring,
        'ITCH' => :Technician,
        'IWMU' => :WatermarkURL,
        'IWRI' => :WrittenBy,
        'LANG' => :Language,
        'LOCA' => :Location,
        'PRT1' => :Part,
        'PRT2' => :NumberOfParts,
        'RATE' => :Rate,
        'STAR' => :Starring,
        'STAT' => :Statistics,
        'TAPE' => :TapeName,
        'TCDO' => :EndTimecode,
        'TCOD' => :StartTimecode,
        'TITL' => :Title,
        'TLEN' => :Length,
        'TORG' => :Organization,
        'TRCK' => :TrackNumber,
        'TURL' => :URL,
        'TVER' => :Version,
        'VMAJ' => :VegasVersionMajor,
        'VMIN' => :VegasVersionMinor,
        'YEAR' => :Year,
        # Exif tags
        'ecor' => :Make,
        'emdl' => :Model,
        'emnt' => :MakerNotes,
        'erel' => :RelatedImageFile,
        'etim' => :TimeCreated,
        'eucm' => :UserComment,
        'ever' => :ExifVersion
      }

      # Wave elements
      ELEMENT_ID_WAVE = 'WAVE'
      ELEMENT_ID_FORMAT = 'fmt '
      ELEMENT_ID_DATA = 'data'
      ELEMENT_ID_FACT = 'fact'

      # AVI elements
      ELEMENT_ID_AVI = 'AVI '
      ELEMENT_ID_STRH = 'strh'
      ELEMENT_ID_STRF = 'strf'
      ELEMENT_ID_MOVI = 'movi'
      ELEMENT_ID_IDX1 = 'idx1'
      ELEMENT_ID_DMLH = 'dmlh'
      ELEMENT_ID_IDIT = 'IDIT'
      HDLR_ELEMENTS = {
        ELEMENT_ID_IDIT => nil,
        'ISMP' => nil,
        'avih' => nil
      }
      STREAM_ELEMENTS = {
        'strd' => nil,
        'strf' => nil,
        'strh' => nil,
        'strn' => nil,
        'indx' => nil
      }
      ODML_IDX_ELEMENTS = {}
      100.times do |idx|
        ODML_IDX_ELEMENTS[sprintf('ix%.2d', idx)] = nil
      end

      # ANI elements
      ELEMENT_ID_ANI = 'ACON'
      ELEMENT_ID_ANIH = 'anih'
      ELEMENT_ID_ICON = 'icon'
      ELEMENT_ID_SEQ = 'seq '
      ELEMENT_ID_RATE = 'rate'

      RIFF_INFO_ELEMENTS = {}
      INFO_ELEMENTS_ID.keys.each do |info_element_id|
        RIFF_INFO_ELEMENTS[info_element_id] = nil
      end
      ELEMENT_ID_LIST = 'LIST'
      RIFF_GENERIC_ELEMENTS = {
        BEGIN_PATTERN_JUNK => nil,
        ELEMENT_ID_LIST => {
          'INFO' => RIFF_INFO_ELEMENTS,
          # AVI elements
          'hdrl' => HDLR_ELEMENTS,
          'strl' => STREAM_ELEMENTS,
          ELEMENT_ID_MOVI => nil,
          'ncdt' => { :element_info => { :ignore_unknown_elements => true } },
          'odml' => {
            ELEMENT_ID_DMLH => nil
          },
          # ANI elements
          'fram' => {
            ELEMENT_ID_ICON => nil
          }
        }.merge(ODML_IDX_ELEMENTS)
      }

      RIFF_ROOT_ELEMENTS = {
        # Wave elements
        ELEMENT_ID_WAVE => {
          ELEMENT_ID_FORMAT => nil,
          ELEMENT_ID_DATA => nil,
          ELEMENT_ID_FACT => nil
        },
        # AVI elements
        ELEMENT_ID_AVI => nil,
        ELEMENT_ID_IDX1 => nil,
        # ANI elements
        ELEMENT_ID_ANI => {
          ELEMENT_ID_ANIH => nil,
          ELEMENT_ID_SEQ => nil,
          ELEMENT_ID_RATE => nil
        }
      }
      RIFF_ELEMENTS = {
        BEGIN_PATTERN_RIFF => RIFF_ROOT_ELEMENTS,
        BEGIN_PATTERN_RIFX => RIFF_ROOT_ELEMENTS
      }

      RIFF_ELEMENTS_WITH_SIZE = [
        BEGIN_PATTERN_RIFF,
        BEGIN_PATTERN_RIFX,
        BEGIN_PATTERN_JUNK,
        ELEMENT_ID_LIST,
        # WAVE elements
        ELEMENT_ID_FORMAT,
        ELEMENT_ID_DATA,
        ELEMENT_ID_FACT,
        # AVI elements
        ELEMENT_ID_IDX1,
        ELEMENT_ID_DMLH,
        # ANI elements
        ELEMENT_ID_ANIH,
        ELEMENT_ID_ICON,
        ELEMENT_ID_SEQ,
        ELEMENT_ID_RATE
      ] +
        RIFF_INFO_ELEMENTS.keys +
        HDLR_ELEMENTS.keys +
        STREAM_ELEMENTS.keys +
        ODML_IDX_ELEMENTS.keys

      AVI_STREAM_TYPES = [ 'db', 'dc', 'pc', 'wb' ]

      TRAILING_00_REGEXP = Regexp.new("\x00*$".force_encoding(Encoding::ASCII_8BIT), nil, 'n')

      def get_begin_pattern
        return BEGIN_PATTERN_FILE, { :offset_inc => 4, :max_regexp_size => 4 }
      end

      def decode(offset)
        ending_offset = nil

        # Check endianness
        name = @data[offset..offset+3]
        @bindata_16 = BinData::Uint16le
        @bindata_32 = BinData::Uint32le
        if (name == BEGIN_PATTERN_RIFX)
          @bindata_16 = BinData::Uint16be
          @bindata_32 = BinData::Uint32be
        end

        # Parse RIFF
        found_RIFF = false
        found_WAVE_data = false
        found_AVI_data = false
        extension = nil
        cursor, nbr_elements = parse_riff_element(offset, RIFF_ELEMENTS) do |element_hierarchy, element_cursor, size, container_end_offset|
          element_name = element_hierarchy[-1]
          if ((element_name == BEGIN_PATTERN_RIFF) or
              (element_name == BEGIN_PATTERN_RIFX))
            # Check we are not getting on a second RIFF file
            if found_RIFF
              ending_offset = element_cursor - 8
              next nil
            end
            found_RIFF = true
          elsif (INFO_ELEMENTS_ID[element_name] != nil)
            # Standard info
            metadata( INFO_ELEMENTS_ID[element_name] => read_ascii(element_cursor, size) )
          else
            # Special cases
            case element_name

            # Wave elements
            when ELEMENT_ID_WAVE
              extension = :wav
              found_relevant_data(extension)
            when ELEMENT_ID_FORMAT
              invalid_data("@#{cursor} - Wave file having an invalid fmt size: #{size}") if (size < 16)
              # Decode header
              audio_format = @bindata_16.read(@data[element_cursor..element_cursor+1])
              num_channels = @bindata_16.read(@data[element_cursor+2..element_cursor+3])
              sample_rate = @bindata_32.read(@data[element_cursor+4..element_cursor+7])
              byte_rate = @bindata_32.read(@data[element_cursor+8..element_cursor+11])
              block_align = @bindata_16.read(@data[element_cursor+12..element_cursor+13])
              bits_per_sample = @bindata_16.read(@data[element_cursor+14..element_cursor+15])
              metadata(
                :audio_format => audio_format,
                :num_channels => num_channels,
                :sample_rate => sample_rate,
                :byte_rate => byte_rate,
                :block_align => block_align,
                :bits_per_sample => bits_per_sample
              )
            when ELEMENT_ID_DATA
              found_WAVE_data = true

            # AVI elements
            when ELEMENT_ID_AVI
              extension = :avi
              found_relevant_data(:avi)
            when ELEMENT_ID_MOVI
              # Parse the following RIFF tags manually
              cursor = element_cursor
              stream_id = @data[cursor..cursor+1]
              stream_type = @data[cursor+2..cursor+3]
              while ((cursor < container_end_offset) and
                     (stream_id.match(/^\d\d$/) != nil) and
                     (AVI_STREAM_TYPES.include?(stream_type)))
                # Read size
                stream_size = @bindata_32.read(@data[cursor+4..cursor+7])
                log_debug "@#{cursor} - Found AVI stream #{stream_id}#{stream_type} of size #{stream_size}"
                cursor += 8 + stream_size
                stream_id = @data[cursor..cursor+1]
                stream_type = @data[cursor+2..cursor+3]
              end
              found_AVI_data = true
              next cursor
            when ELEMENT_ID_IDIT
              metadata( :date_time_original => read_ascii(element_cursor, size) )

            # ANI elements
            when ELEMENT_ID_ANI
              extension = :ani
              found_relevant_data(:ani)

            end

          end

          # By default: no data
          next element_cursor
        end
        metadata( :nbr_elements => nbr_elements )
        invalid_data("@#{cursor} - Missing WAVE data.") if ((extension == :wav) and (!found_WAVE_data))
        invalid_data("@#{cursor} - Missing AVI data.") if ((extension == :avi) and (!found_AVI_data))
        ending_offset = cursor if (ending_offset == nil)

        return ending_offset
      end

      private

      # Parse a RIFF element, calling a callback for each sub-element read (recursively)
      #
      # Parameters::
      # * *cursor* (_Fixnum_): Current parsing cursor
      # * *element_names* (<em>map<String,Object></em>): Possible element names, with their possible sub-elements (or nil if none).
      # * *hierarchy* (<em>list<String></em>): The hierarchy of element names leading to this element [default = []]
      # * *max_cursor* (_Fixnum_): Maximal cursor for the element. This is set using the size of the element containing the ones being parsed. Can be nil if unknown. [default = nil]
      # * *&proc* (_Proc_): Code block called for each box encountered.
      #   * Parameters::
      #   * *element_hierarchy* (<em>list<String></em>): Complete element names hierarchy leading to this element
      #   * *element_cursor* (_Fixnum_): Cursor of the beginning of this element data
      #   * *element_size* (_Fixnum_): Size of this element data
      #   * *container_end_offset* (_Fixnum_): End offset of this element's container
      #   * Result::
      #   * _Fixnum_: The cursor ending parsing this element, or nil to stop the parsing
      # Result::
      # * _Fixnum_: The new cursor after having parsed this element, or nil to stop the parsing
      # * _Fixnum_: The number of elements parsed
      def parse_riff_element(cursor, element_names, hierarchy = [], max_cursor = nil, &proc)
        nbr_elements = 0
        nbr_direct_subelements = 0
        container_element_max_cursor = ((max_cursor == nil) ? @end_offset : max_cursor)
        # Compute the map of possible element names
        complete_element_names = element_names.merge(RIFF_GENERIC_ELEMENTS)
        ignore_unknown_elements = ((element_names[:element_info] != nil) and (element_names[:element_info][:ignore_unknown_elements] = true))
        while (cursor < container_element_max_cursor)
          name = @data[cursor..cursor+3]
          # Check the validity of the element
          if ((!ignore_unknown_elements) and
              (!complete_element_names.has_key?(name)))
            log_debug "@#{cursor} - Invalid element name: #{name.inspect} within #{hierarchy.join('/')}. Known ones are: #{complete_element_names.keys.join(', ')}."
            if (max_cursor == nil)
              # We consider the file is finished, as the element being parsed is the root one.
              return cursor, nbr_elements
            else
              truncated_data("@#{cursor} - No valid element found, but container element has not been parsed completely.")
            end
          end
          # If there is a size, read it
          # Consider that if we ignore unknown elements they all HAVE a size
          size = ((ignore_unknown_elements or (RIFF_ELEMENTS_WITH_SIZE.include?(name))) ? @bindata_32.read(@data[cursor+4..cursor+7]) : nil)
          # This element is valid
          nbr_elements += 1
          nbr_direct_subelements += 1
          element_hierarchy = hierarchy + [name]
          cursor += 4
          cursor += 4 if (size != nil)
          element_cursor = cursor
          log_debug "@#{cursor} - Found element #{element_hierarchy.join('/')} of size #{size} - Data: #{@data[element_cursor..element_cursor+(((size != nil) and (size < 32)) ? size : ((@end_offset-element_cursor < 32) ? @end_offset-element_cursor : 32))-1].inspect}"
          # Parse this element's data
          element_cursor_end = yield(element_hierarchy, element_cursor, size, container_element_max_cursor)
          if (element_cursor_end == nil)
            cursor = nil
            break
          end
          invalid_data("@#{cursor} - Element parsing exceeded its element's size (#{element_cursor_end} > #{element_cursor + size})") if ((size != nil) and (element_cursor_end > element_cursor + size))
          invalid_data("@#{cursor} - Element parsing exceeded its container limit (#{element_cursor_end} > #{container_element_max_cursor})") if (element_cursor_end > container_element_max_cursor)
          cursor = element_cursor_end
          if ((complete_element_names[name] != nil) and
              (cursor < container_element_max_cursor))
            # Now call sub-elements that should start at current cursor
            new_cursor, nbr_subelements = parse_riff_element(cursor, complete_element_names[name], element_hierarchy, (size == nil) ? container_element_max_cursor : element_cursor + size, &proc)
            nbr_elements += nbr_subelements
            cursor = new_cursor
            break if (new_cursor == nil)
            # Check cursor is at the correct position
            invalid_data("@#{cursor} - Element parsing should have stopped at #{element_cursor + size} but is instead at #{cursor}") if ((size != nil) and (cursor != element_cursor + size))
          end
          truncated_data("@#{cursor} - Element #{element_hierarchy.join('/')} with size #{size} finishes at cursor #{element_cursor + size}, but container element set maximal cursor to #{container_element_max_cursor}.") if ((size != nil) and (element_cursor + size > container_element_max_cursor))
          cursor = element_cursor + size if (size != nil)
          progress(cursor)
        end

        return cursor, nbr_elements
      end

      # Read an ASCII value
      #
      # Parameters::
      # * *cursor* (_Fixnum_): The cursor to read from
      # * *size* (_Fixnum_): Size of the string
      # Result::
      # * _String_ or <em>list<String></em>: Resulting string or list of strings if several.
      def read_ascii(cursor, size)
        return @data[cursor..cursor+size-1].gsub(TRAILING_00_REGEXP, '').strip
      end

    end

  end

end
