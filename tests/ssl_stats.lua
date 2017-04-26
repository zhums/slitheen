--------------------------------------------------
-- Author: Cecylia Bocovich <cbocovic@uwaterloo.ca>
-- Purpose: Extracts statistics about TLS handshakes
-- Usage: tshark -q <other opts> -Xlua_script:tls_stats.lua -r <trace>
--------------------------------------------------

do
    -- Extractor definitions
    ip_addr_extractor = Field.new("ip.addr")
    tcp_src_port_extractor = Field.new("tcp.srcport")
    tcp_dst_port_extractor = Field.new("tcp.dstport")
    tcp_stream_extractor = Field.new("tcp.stream")
    tls_handshake_type_extractor = Field.new("ssl.handshake.type")
    tls_record_type_extractor = Field.new("ssl.record.content_type")
    tls_session_id_extractor = Field.new("ssl.handshake.session_id")
    tls_ccs_extractor = Field.new("ssl.change_cipher_spec")
    icmp_type_extractor = Field.new("icmp.type")

    -- TLS states
    CLNT_HELLO = "1"
    SRVR_HELLO = "2"
    NEW_SESSION = "4"
    CERT = "11"
    SRVR_KEYEX = "12"
    SRVR_DONE = "14"
    CLNT_KEYEX = "16"

    -- Record types
    CCS = "20"
    ALERT = "21"
    HANDSHAKE = "22"
    APPLICATION = "23"

    local function main()
        local tap = Listener.new("ssl")

        local file = assert(io.open("handshake_stats", "w"))
        file:write("stream,time\n")
        file:close()

        --------------------------------
        ----- Handshake Statistics -----
        --------------------------------

        -- Each stream has a table that holds the following data:
        -- {state = [SHAKING, SHOOK, APPLICATION],
        --  clnt_session_id = [Bytes], srvr_session_id = [Bytes],
        --  session_ticket = [Bytes], resumed = [Boolean],
        --  ccs_received = [Int],
        --  start_time = [Float], end_time = [Float], shake_time = [Float]}

        local streams = {} -- Table that holds all stream tables
        local tls_src_starts = {}
        function stats_tls_handshake(pinfo, tvb)
            local ip_src, ip_dst = ip_addr_extractor()
            local port_src = tcp_src_port_extractor()
            local port_dst = tcp_dst_port_extractor()
            local stream = tostring(tcp_stream_extractor())
            -- check if stream is already saved
            local stream_info
            if(not streams[stream]) then
                streams[stream] = {}
                streams[stream]["state"] = "shaking"
                streams[stream]["client_ip"] = tostring(ip_src)
                streams[stream]["server_ip"] = tostring(ip_dst)
                streams[stream]["client_port"] = tostring(port_src)
                streams[stream]["server_port"] = tostring(port_dst)
            end
            stream_info = streams[stream]

            local rec_type = tls_record_type_extractor()
            local ccs = tls_ccs_extractor()
            if( not rec_type) then do return end end
            rec_type = tostring(rec_type)

            if (rec_type == HANDSHAKE) then
                local hs_type = tostring(tls_handshake_type_extractor())
                if (hs_type == CLNT_HELLO) then
                    stream_info["start_time"] = pinfo.abs_ts
                    local clnt_sess_id = tls_session_id_extractor()
                    if(clnt_sess_id) then
                        stream_info["clnt_sess_id"] = clnt_sess_id
                    end
                elseif (hs_type == SRVR_HELLO) then
                    local srvr_sess_id = tls_session_id_extractor()
                    if(srvr_sess_id) then
                        if(stream_info["clnt_sess_id"] == srvr_sess_id) then
                            stream_info["resumed"] = true
                        end
                    end
                end
            end
            if (ccs) then
                --check to see if this is the first or second CCS
                if(not stream_info["ccs_received"]) then
                    stream_info["ccs_received"] = 1
                elseif (stream_info["ccs_received"] == 1) then
                    -- handshake has ended
                    stream_info["end_time"] = pinfo.abs_ts
                    stream_info["shake_time"] = stream_info["end_time"] - stream_info["start_time"];
                    stream_info["state"] = "SHOOK"
                end
            end

            if (rec_type == APPLICATION) then
                if(not stream_info["app_start_time"]) then
                    -- this is the first application data
                    stream_info["app_start_time"] = pinfo.abs_ts
                    stream_info["state"] = "APP"
                elseif( (not stream_info["app_rtt_time"]) and (tostring(ip_src) ~= stream_info["client_ip"]) ) then
                    stream_info["app_rtt_time"] = pinfo.abs_ts - stream_info["app_start_time"]
                end

            end
            
        end

        -- start/end times
        local start_time
        local end_time
        function stats_start_end_times(pinfo)
            if (not start_time) then
                start_time =  pinfo.abs_ts
                end_time  =  pinfo.abs_ts
            else
                if ( start_time > pinfo.abs_ts ) then start_time = pinfo.abs_ts end
                if ( end_time < pinfo.abs_ts  ) then end_time = pinfo.abs_ts end
            end
        end

        function print_resumed_session_stats()
            for stream in pairs(streams) do
                stream_info = streams[stream]
                if (stream_info["resumed"]) then
                    print(stream .. "," .. tostring(stream_info["shake_time"]))
                end
            end
        end

        function print_nonresumed_session_stats()
            for stream in pairs(streams) do
                stream_info = streams[stream]
                if (not stream_info["resumed"]) then
                    print(stream .. "," .. tostring(stream_info["shake_time"]))
                end
            end
        end

        function print_application_stats()
            for stream in pairs(streams) do
                stream_info = streams[stream]
                if (stream_info["app_rtt_time"]) then
                    print(stream .. "," .. tostring(stream_info["app_rtt_time"]))
                end
            end
        end

        function print_stream_info()
            for stream in pairs(streams) do
                stream_info = streams[stream]
                print("Stream " .. stream .. ": " .. stream_info["client_ip"] .. ":" .. stream_info["client_port"] .. " > " .. stream_info["server_ip"] .. ":" .. stream_info["server_port"])
            end
        end

-------------------
----- tap functions
-------------------
        function tap.reset()
        end

        function tap.packet(pinfo,tvb,ip)
            stats_start_end_times(pinfo)
            stats_tls_handshake(pinfo, tvb)
        end

        function tap.draw()
            --print("=== Stream Information ===")
            --print_stream_info()
            print("=== Handshake Statistics ===")
            print("Capture Start Time: " .. tostring(start_time) )
            print("Capture End Time: " .. tostring(end_time) )

            print("=== Full Handshakes ===")
            print_nonresumed_session_stats()
            print("=== Resumed sessions ===")
            print_resumed_session_stats()
            print("\n")
            print("=== Application Statistics ===")
            print_application_stats()
        end
    end

    main()
end
