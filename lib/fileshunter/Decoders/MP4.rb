module FilesHunter

  module Decoders

    class MP4 < BeginPatternDecoder

      BEGIN_PATTERN_MOV_1 = 'pnot'.force_encoding(Encoding::ASCII_8BIT)
      BEGIN_PATTERN_MOV_2 = 'mdat'.force_encoding(Encoding::ASCII_8BIT)
      BEGIN_PATTERN_MOV_3 = 'moov'.force_encoding(Encoding::ASCII_8BIT)
      BEGIN_PATTERN_MP4 = Regexp.new("(ftyp|#{BEGIN_PATTERN_MOV_1}|#{BEGIN_PATTERN_MOV_2}|#{BEGIN_PATTERN_MOV_3})", nil, 'n')

      # List taken from http://www.iso.org/iso/home/store/catalogue_ics/catalogue_detail_ics.htm?csnumber=61988
      # Completed with http://xhelmboyx.tripod.com/formats/mp4-layout.txt
      # Completed with http://www.etsi.org/deliver/etsi_ts/126200_126299/126244/10.02.00_60/ts_126244v100200p.pdf
      # Completed with https://developer.apple.com/library/mac/#documentation/QuickTime/QTFF/QTFFChap2/qtff2.html
      ACCEPTABLE_BOX_TYPES_ALL = {
        'free' => nil,
        'skip' => nil
      }
      ACCEPTABLE_BOX_TYPES_UDTA = { :box_info => { :ignore_unknown_boxes => true, :nbr_bytes_possible_padding => 4 },
        'cprt' => nil,
        'tsel' => nil,
        'strk' => {
          'stri' => nil,
          'strd' => nil
        },
        # Following were completed but are not part of ISO
        'albm' => nil,
        'AllF' => nil,
        'auth' => nil,
        'clsf' => nil,
        'coll' => nil,
        'dscp' => nil,
        'gnre' => nil,
        'hinf' => nil,
        'hnti' => nil,
        'kywd' => nil,
        'loci' => nil,
        'LOOP' => nil,
        'name' => nil,
        'perf' => nil,
        'ptv ' => nil,
        'rtng' => nil,
        'SelO' => nil,
        'tagc' => nil,
        'thmb' => nil,
        'titl' => nil,
        'tnam' => nil,
        'urat' => nil,
        'WLOC' => nil,
        'yrrc' => nil,
        "\xA9arg" => nil,
        "\xA9ark" => nil,
        "\xA9cok" => nil,
        "\xA9com" => nil,
        "\xA9cpy" => nil,
        "\xA9day" => nil,
        "\xA9dir" => nil,
        "\xA9ed1" => nil,
        "\xA9ed2" => nil,
        "\xA9ed3" => nil,
        "\xA9ed4" => nil,
        "\xA9ed5" => nil,
        "\xA9ed6" => nil,
        "\xA9ed7" => nil,
        "\xA9ed8" => nil,
        "\xA9ed9" => nil,
        "\xA9fmt" => nil,
        "\xA9inf" => nil,
        "\xA9isr" => nil,
        "\xA9lab" => nil,
        "\xA9lal" => nil,
        "\xA9mak" => nil,
        "\xA9mal" => nil,
        "\xA9nak" => nil,
        "\xA9nam" => nil,
        "\xA9pdk" => nil,
        "\xA9phg" => nil,
        "\xA9prd" => nil,
        "\xA9prf" => nil,
        "\xA9prk" => nil,
        "\xA9prl" => nil,
        "\xA9req" => nil,
        "\xA9snk" => nil,
        "\xA9snm" => nil,
        "\xA9src" => nil,
        "\xA9swf" => nil,
        "\xA9swk" => nil,
        "\xA9swr" => nil,
        "\xA9wrt" => nil,
        'meta' => { :box_info => { :data_size => 4 },
          'hdlr' => nil,
          'xml ' => nil,
          'bxml' => nil,
          'iloc' => nil,
          'pitm' => nil,
          'ipro' => { :box_info => { :data_size => 6, :nbr_children_range => [4, 5] },
            'sinf' => {
              'frma' => nil,
              'imif' => nil,
              'schm' => nil,
              'schi' => nil
            }
          },
          'ilst' => {
            "\xA9nam" => { 'data' => nil, 'mean' => nil, 'name' => nil },
            "\xA9cmt" => { 'data' => nil, 'mean' => nil, 'name' => nil },
            "\xA9day" => { 'data' => nil, 'mean' => nil, 'name' => nil },
            "\xA9ART" => { 'data' => nil, 'mean' => nil, 'name' => nil },
            "\xA9trk" => { 'data' => nil, 'mean' => nil, 'name' => nil },
            "\xA9alb" => { 'data' => nil, 'mean' => nil, 'name' => nil },
            "\xA9com" => { 'data' => nil, 'mean' => nil, 'name' => nil },
            "\xA9wrt" => { 'data' => nil, 'mean' => nil, 'name' => nil },
            "\xA9too" => { 'data' => nil, 'mean' => nil, 'name' => nil },
            'gnre' => { 'data' => nil, 'mean' => nil, 'name' => nil },
            'disk' => { 'data' => nil, 'mean' => nil, 'name' => nil },
            'trkn' => { 'data' => nil, 'mean' => nil, 'name' => nil },
            'tmpo' => { 'data' => nil, 'mean' => nil, 'name' => nil },
            'cpil' => { 'data' => nil, 'mean' => nil, 'name' => nil },
            'covr' => { 'data' => nil, 'mean' => nil, 'name' => nil },
            '----' => { 'data' => nil, 'mean' => nil, 'name' => nil }
          }
        },
        # Following were encountered but not documented
        'CNCV' => nil,
        'CNDB' => nil,
        'CNFV' => nil,
        'CNMN' => nil,
        'hinv' => nil,
        'TAGS' => nil
      }
      ACCEPTABLE_BOX_TYPES = {
        'ftyp' => nil,
        'pdin' => nil,
        'moov' => {
          'mvhd' => nil,
          'trak' => {
            'tkhd' => nil,
            'tref' => {
              # Following were completed but are not part of ISO
              'hint' => nil,
              'dpnd' => nil,
              'ipir' => nil,
              'mpod' => nil,
              'sync' => nil,
              'tmcd' => nil,
              'chap' => nil,
              'scpt' => nil,
              'ssrc' => nil
            },
            'trgr' => nil,
            'edts' => {
              'elst' => nil
            },
            'mdia' => {
              'mdhd' => nil,
              'hdlr' => nil,
              'minf' => {
                'vmhd' => nil,
                'smhd' => nil,
                'hmhd' => nil,
                'nmhd' => nil,
                'dinf' => {
                  'dref' => { :box_info => { :data_size => 8, :nbr_children_range => [4, 7] },
                    # Following were completed but are not part of ISO
                    'url ' => nil,
                    'urn ' => nil,
                    'alis' => nil,
                    'rsrc' => nil
                  },
                  # Following were completed but are not part of ISO
                  'url ' => nil,
                  'urn ' => nil
                },
                'stbl' => {
                  'stsd' => nil,
                  # To complex to be parsed
                  # 'stsd' => {
                  #   # Following were completed but are not part of ISO
                  #   'sinf' => {
                  #     'frma' => nil,
                  #     'imif' => nil,
                  #     'schm' => nil,
                  #     'schi' => nil
                  #   },
                  #   'd263' => {
                  #     'bitr' => nil
                  #   },
                  #   'damr' => nil,
                  #   'avcC' => nil,
                  #   'esds' => nil,
                  #   'm4ds' => nil,
                  #   'gama' => nil,
                  #   'fiel' => nil,
                  #   'mjqt' => nil,
                  #   'mjht' => nil
                  # },
                  'stts' => nil,
                  'ctts' => nil,
                  'cslg' => nil,
                  'stsc' => nil,
                  'stsz' => nil,
                  'stz2' => nil,
                  'stco' => nil,
                  'co64' => nil,
                  'stss' => nil,
                  'stsh' => nil,
                  'padb' => nil,
                  'stdp' => nil,
                  'sdtp' => nil,
                  'sbgp' => nil,
                  'sgpd' => nil,
                  'subs' => nil,
                  'saiz' => nil,
                  'saio' => nil
                },
                # Following were completed but are not part of ISO
                'hint' => nil,
                'hdlr' => nil
              }
            },
            'udta' => ACCEPTABLE_BOX_TYPES_UDTA,
            # Following were completed but are not part of ISO
            'clip' => nil,
            'matt' => {
              'kmat' => nil
            },
            'load' => nil,
            'imap' => {
              "\x00\x00in" => { :box_info => { :data_size => 12 },
                "\x00\x00ty" => nil,
                'obid' => nil
              }
            }
          },
          'mvex' => {
            'mehd' => nil,
            'trex' => nil,
            'leva' => nil
          },
          # Following were completed but are not part of ISO
          'mdra' => {
            'dref' => nil
          },
          'cmov' => {
            'dcom' => nil,
            'cmvd' => nil
          },
          'rmra' => {
            'rmda' => {
              'rdrf' => nil,
              'rmqu' => nil,
              'rmcs' => nil,
              'rmvc' => nil,
              'rmcd' => nil,
              'rmdr' => nil,
              'rmla' => nil,
              'rmag' => nil
            }
          },
          'iods' => nil,
          'clip' => {
            'crgn' => nil
          },
          'udta' => ACCEPTABLE_BOX_TYPES_UDTA
        },
        'moof' => {
          'mfhd' => nil,
          'traf' => {
            'tfhd' => nil,
            'trun' => nil,
            'sbgp' => nil,
            'sgpd' => nil,
            'subs' => nil,
            'saiz' => nil,
            'saio' => nil,
            'tfdt' => nil
          }
        },
        'mfra' => {
          'tfra' => nil,
          'mfro' => nil
        },
        'mdat' => nil,
        'meta' => { :box_info => { :data_size => 4 },
          'hdlr' => nil,
          'dinf' => {
            'dref' => nil
          },
          'iloc' => nil,
          'ipro' => { :box_info => { :data_size => 6, :nbr_children_range => [4, 5] },
            'sinf' => {
              'frma' => nil,
              'schm' => nil,
              'schi' => nil,
              # Following were completed but are not part of ISO
              'imif' => nil
            }
          },
          'iinf' => nil,
          'xml ' => nil,
          'bxml' => nil,
          'pitm' => nil,
          'fiin' => {
            'paen' => {
              'fire' => nil,
              'fpar' => nil,
              'fecr' => nil
            },
            'segr' => nil,
            'gitn' => nil
          },
          'idat' => nil,
          'iref' => nil
        },
        'meco' => {
          'mere' => nil
        },
        'styp' => nil,
        'sidx' => nil,
        'ssix' => nil,
        'prft' => nil,
        # Following were completed but are not part of ISO
        'wide' => nil,
        # Following were encountered but not documented
        'PICT' => nil,
        'pnot' => nil
      }

      # List taken from here: http://www.ftyps.com/
      KNOWN_EXTENSIONS = {
        '3g2a' => '3g2',
        '3g2b' => '3g2',
        '3g2c' => '3g2',
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
        return BEGIN_PATTERN_MP4, { :begin_pattern_offset_in_segment => 4, :offset_inc => 4 }
      end

      def decode(offset)
        ending_offset = nil

        found_ftyp = false
        found_mdat = false
        valid_mp4 = false
        ending_offset, nbr_boxes = parse_mp4_box(offset, ACCEPTABLE_BOX_TYPES) do |box_hierarchy, box_cursor, box_size|
          # If we browsed enough in the file, mark it as valid
          if ((!valid_mp4) and
              (box_hierarchy.size > 2))
            valid_mp4 = true
            found_relevant_data(:mov) if (!found_ftyp)
          end
          # Get data from parsed boxes
          case box_hierarchy[-1]
          when 'mdat'
            found_mdat = true
            metadata( :mdat_size => box_size )
          when 'ftyp'
            # Get the extension
            ftyp_id = @data[box_cursor+8..box_cursor+11]
            log_debug "@#{box_cursor} - Found ftyp #{ftyp_id}."
            known_extension = KNOWN_EXTENSIONS[ftyp_id]
            invalid_data("@#{box_cursor} - Unknown MP4 ftyp: #{ftyp_id}") if (known_extension == nil)
            found_relevant_data(known_extension.to_sym)
            found_ftyp = true
          when 'mvhd'
            version = @data[box_cursor+8].ord
            flags = BinData::Uint24be.read(@data[box_cursor+9..box_cursor+11])
            cursor = box_cursor + 12
            creation_time = nil
            modification_time = nil
            timescale = nil
            duration = nil
            if (version == 0)
              creation_time = BinData::Uint32be.read(@data[cursor..cursor+3])
              modification_time = BinData::Uint32be.read(@data[cursor+4..cursor+7])
              timescale = BinData::Uint32be.read(@data[cursor+8..cursor+11])
              duration = BinData::Uint32be.read(@data[cursor+12..cursor+15])
              cursor += 16
            else
              creation_time = BinData::Uint64be.read(@data[cursor..cursor+7])
              modification_time = BinData::Uint64be.read(@data[cursor+8..cursor+15])
              timescale = BinData::Uint32be.read(@data[cursor+16..cursor+19])
              duration = BinData::Uint64be.read(@data[cursor+20..cursor+27])
              cursor += 28
            end
            rate = BinData::Uint32be.read(@data[cursor..cursor+3])
            volume = BinData::Uint16be.read(@data[cursor+4..cursor+5])
            metadata(
              :creation_time => creation_time,
              :modification_time => modification_time,
              :timescale => timescale,
              :duration => duration,
              :rate => rate,
              :volume => volume
            )
          when 'CNCV'
            metadata( :CNCV => @data[box_cursor+8..box_cursor+box_size-1] )
          when 'CNMN'
            metadata( :CNMN => @data[box_cursor+8..box_cursor+box_size-1].gsub("\x00", '').strip )
          when 'CNCV'
            metadata( :CNCV => @data[box_cursor+8..box_cursor+box_size-1].gsub("\x00", '').strip )
          when "\xA9fmt"
            metadata( :fmt => @data[box_cursor+12..box_cursor+box_size-1].strip )
          when "\xA9inf"
            metadata( :inf => @data[box_cursor+12..box_cursor+box_size-1].strip )
          end
        end
        # An MP4 without ftyp is surely a .mov
        found_relevant_data(:mov) if (!found_ftyp)
        metadata(
          :nbr_boxes => nbr_boxes
        )
        truncated_data("@#{ending_offset} - Missing mdat box.") if (!found_mdat)
        # TODO: Find a way to detect the end of a stream (usually size 0 applies to mdat boxes)
        invalid_data('Cannot decode MP4 to the end of file') if (ending_offset == nil)

        return ending_offset
      end

      private

      # Parse a MP4 box, calling a callback for each sub-box read (recursively)
      #
      # Parameters::
      # * *cursor* (_Fixnum_): Current parsing cursor
      # * *box_names* (<em>map<String,Object></em>): Possible box names, with their possible sub-boxes (or nil if none).
      # * *hierarchy* (<em>list<String></em>): The hierarchy of box names leading to this box [default = []]
      # * *max_cursor* (_Fixnum_): Maximal cursor for the box. This is set using the size of the box containing the ones being parsed. Can be nil if unknown. [default = nil]
      # * *&proc* (_Proc_): Code block called for each box encountered.
      #   * Parameters::
      #   * *box_hierarchy* (<em>list<String></em>): Complete box names hierarchy leading to this box
      #   * *box_cursor* (_Fixnum_): Cursor of the beginning of this box (including size and name)
      #   * *box_size* (_Fixnum_): Size of this box (including size and name)
      # Result::
      # * _Fixnum_: The new cursor after having parsed this box. Can be nil if the size of one of the sub-boxes is unknown.
      # * _Fixnum_: The number of boxes parsed
      def parse_mp4_box(cursor, box_names, hierarchy = [], max_cursor = nil, &proc)
        #log_debug "=== @#{cursor} - Parsing #{@data[cursor..cursor+31].inspect} ..."
        nbr_boxes = 0
        nbr_direct_subboxes = 0
        container_box_max_cursor = ((max_cursor == nil) ? @end_offset : max_cursor)
        # Compute the size of data before looking for sub-boxes
        data_size = 0
        data_size += box_names[:box_info][:data_size] if ((box_names[:box_info] != nil) and (box_names[:box_info][:data_size] != nil))
        nbr_expected_subboxes = nil
        if ((box_names[:box_info] != nil) and
            (box_names[:box_info][:nbr_children_range] != nil))
          str_nbr_subboxes = @data[cursor+box_names[:box_info][:nbr_children_range][0]..cursor+box_names[:box_info][:nbr_children_range][1]]
          case str_nbr_subboxes.size
          when 1
            nbr_expected_subboxes = str_nbr_subboxes.ord
          when 2
            nbr_expected_subboxes = BinData::Uint16be.read(str_nbr_subboxes)
          when 3
            nbr_expected_subboxes = BinData::Uint24be.read(str_nbr_subboxes)
          when 4
            nbr_expected_subboxes = BinData::Uint32be.read(str_nbr_subboxes)
          when 8
            nbr_expected_subboxes = BinData::Uint64be.read(str_nbr_subboxes)
          else
            # Can't read it. Will not check for them.
          end
        end
        cursor += data_size
        # Compute the map of possible box names
        complete_box_names = box_names.merge(ACCEPTABLE_BOX_TYPES_ALL)
        while (cursor < container_box_max_cursor)
          size = BinData::Uint32be.read(@data[cursor..cursor+3])
          name = @data[cursor+4..cursor+7]
          # Check the validity of the box
          if (!complete_box_names.has_key?(name))
            log_debug "@#{cursor} - Invalid box type: #{name.inspect} within #{hierarchy.join('/')}. Known ones are: #{complete_box_names.keys.join(', ')}."
            if ((box_names[:box_info] == nil) or
                (box_names[:box_info][:ignore_unknown_boxes] != true))
              if (max_cursor == nil)
                # We consider the file is finished, as the box being parsed is the root one.
                return cursor, nbr_boxes
              else
                truncated_data("@#{cursor} - No valid box type found, but container box has not been parsed completely.")
              end
            end
          end
          # This box is valid, or we don't care (in this case we will have to skip its contents)
          nbr_boxes += 1
          nbr_direct_subboxes += 1
          box_cursor = cursor
          box_hierarchy = hierarchy + [name]
          log_debug "=== @#{cursor} - Found box #{box_hierarchy.join('/')} of size #{size}"
          cursor += 8
          if (size == 1)
            size = BinData::Uint64be.read(@data[cursor..cursor+7])
            log_debug "=== @#{cursor} - Real size is #{size}"
            cursor += 8
          end
          truncated_data("@#{cursor} - Box #{box_hierarchy.join('/')} with size #{size} should finish at cursor #{box_cursor + size}, but container box set maximal cursor to #{container_box_max_cursor}.") if (box_cursor + size > container_box_max_cursor)
          yield(box_hierarchy, box_cursor, size)
          if (size == 0)
            # Last box, to the end.
            return nil, nbr_boxes
          else
            if (complete_box_names[name] != nil)
              # Now call sub-boxes that should start at current cursor
              new_cursor, nbr_subboxes = parse_mp4_box(cursor, complete_box_names[name], box_hierarchy, box_cursor + size, &proc)
              nbr_boxes += nbr_subboxes
              # Check cursor is at the correct position
              invalid_data("@#{new_cursor} - After parsing box #{box_hierarchy.join('/')}, cursor should have been @#{box_cursor+size}") if ((new_cursor != nil) and (new_cursor != box_cursor + size))
            end
            cursor = box_cursor + size
          end
          # Check for an eventual padding if any
          cursor += box_names[:box_info][:nbr_bytes_possible_padding] if ((box_names[:box_info] != nil) and
            (box_names[:box_info][:nbr_bytes_possible_padding] != nil) and
            (cursor == container_box_max_cursor - box_names[:box_info][:nbr_bytes_possible_padding]) and
            (@data[cursor..container_box_max_cursor-1] == "\x00" * box_names[:box_info][:nbr_bytes_possible_padding]))
          progress(cursor)
        end
        # If we were expecting a given number of direct subboxes, compare them now
        invalid_data("@#{cursor} - Was expecting #{nbr_expected_subboxes} sub-boxes, but read #{nbr_direct_subboxes}.") if ((nbr_expected_subboxes != nil) and (nbr_direct_subboxes != nbr_expected_subboxes))

        return cursor, nbr_boxes
      end

    end

  end

end
