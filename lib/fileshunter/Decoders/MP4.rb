module FilesHunter

  module Decoders

    class MP4 < BeginPatternDecoder

      BEGIN_PATTERN_MP4 = 'ftyp'.force_encoding('ASCII-8BIT')
      BEGIN_PATTERN_MOV_1 = 'pnot'.force_encoding('ASCII-8BIT')
      BEGIN_PATTERN_MOV_2 = 'mdat'.force_encoding('ASCII-8BIT')
      ACCEPTABLE_BOX_TYPES = [
        'free',
        'ftyp',
        'mdat',
        'moov',
        'PICT',
        'pnot'
      ]

      KNOWN_EXTENSIONS = {
        '3g2a' => '3gp',
        '3g2b' => '3gp',
        '3g2c' => '3gp',
        '3ge6' => '3gp',
        '3ge7' => '3gp',
        '3gg6' => '3gp',
        '3gp1' => '3gp',
        '3gp2' => '3gp',
        '3gp3' => '3gp',
        '3gp4' => '3gp',
        '3gp5' => '3gp',
        '3gp6' => '3gp',
        '3gp6' => '3gp',
        '3gp6' => '3gp',
        '3gs7' => '3gp',
        'avc1' => 'mp4',
        'CAEP' => 'mp4',
        'caqv' => 'mp4',
        'CDes' => 'mp4',
        'da0a' => 'mp4',
        'da0b' => 'mp4',
        'da1a' => 'mp4',
        'da1b' => 'mp4',
        'da2a' => 'mp4',
        'da2b' => 'mp4',
        'da3a' => 'mp4',
        'da3b' => 'mp4',
        'dmb1' => 'mp4',
        'dmpf' => 'mp4',
        'drc1' => 'mp4',
        'dv1a' => 'mp4',
        'dv1b' => 'mp4',
        'dv2a' => 'mp4',
        'dv2b' => 'mp4',
        'dv3a' => 'mp4',
        'dv3b' => 'mp4',
        'dvr1' => 'mp4',
        'dvt1' => 'mp4',
        'F4V ' => 'f4v',
        'F4P ' => 'f4p',
        'F4A ' => 'f4a',
        'F4B ' => 'f4b',
        'isc2' => 'mp4',
        'iso2' => 'mp4',
        'isom' => 'mp4',
        'JP2 ' => 'jp2',
        'JP20' => 'jp2',
        'jpm ' => 'jpm',
        'jpx ' => 'jpx',
        'KDDI' => '3gp',
        'M4A ' => 'm4a',
        'M4B ' => 'mp4',
        'M4P ' => 'mp4',
        'M4V ' => 'm4v',
        'M4VH' => 'm4v',
        'M4VP' => 'm4v',
        'mj2s' => 'mj2',
        'mjp2' => 'mj2',
        'mmp4' => 'mp4',
        'mp21' => 'mp4',
        'mp41' => 'mp4',
        'mp42' => 'mp4',
        'mp71' => 'mp4',
        'MPPI' => 'mp4',
        'mqt ' => 'mqv',
        'MSNV' => 'mp4',
        'NDAS' => 'mp4',
        'NDSC' => 'mp4',
        'NDSH' => 'mp4',
        'NDSM' => 'mp4',
        'NDSP' => 'mp4',
        'NDSS' => 'mp4',
        'NDXC' => 'mp4',
        'NDXH' => 'mp4',
        'NDXM' => 'mp4',
        'NDXP' => 'mp4',
        'NDXS' => 'mp4',
        'odcf' => 'mp4',
        'opf2' => 'mp4',
        'opx2' => 'mp4',
        'pana' => 'mp4',
        'qt  ' => 'mov',
        'ROSS' => 'mp4',
        'sdv ' => 'mp4',
        'ssc1' => 'mp4',
        'ssc2' => 'mp4'
      }

      def get_begin_pattern
        return [ BEGIN_PATTERN_MP4, BEGIN_PATTERN_MOV_1, BEGIN_PATTERN_MOV_2 ], { :begin_pattern_offset_in_segment => 4, :offset_inc => 4 }
      end

      def decode(offset)
        ending_offset = nil

        cursor = offset
        found_ftyp = false
        while (ending_offset == nil)
          size = BinData::Uint32be.read(@data[cursor..cursor+3])
          name = @data[cursor+4..cursor+7]
          invalid_data("@#{cursor} - Invalid box type: #{name}") if (!ACCEPTABLE_BOX_TYPES.include?(name))
          if (name == 'ftyp')
            # Get the extension
            known_extension = KNOWN_EXTENSIONS[@data[cursor+8..cursor+11]]
            invalid_data("@#{cursor} - Unknown MP4 ftyp: #{@data[cursor+8..cursor+11]}") if (known_extension == nil)
            found_relevant_data(known_extension.to_sym)
            found_ftyp = true
          end
          log_debug "=== @#{cursor} - Found box #{name} of size #{size}"
          if (size == 0)
            # Last box, to the end. Can't handle it
            invalid_data("@#{cursor} - Can't handle boxes of size 0")
          elsif (size == 1)
            size = BinData::Uint64be.read(@data[cursor+8..cursor+15])
            log_debug "=== @#{cursor} - Real size is #{size}"
          end
          cursor += size
          progress(cursor)
          ending_offset = cursor if (cursor == @end_offset)
        end
        # An MP4 without ftyp is surely a .mov
        found_relevant_data(:mov) if (!found_ftyp)

        return ending_offset
      end

    end

  end

end
