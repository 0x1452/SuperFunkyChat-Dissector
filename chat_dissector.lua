local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_1

local default_settings =
{
    debug_level  = DEBUG,
    enabled      = true, 
    port         = 12345, 
}

local dprint = function() end
local dprint2 = function() end
local function resetDebugLevel()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua: ", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    else
        dprint = function() end
        dprint2 = dprint
    end
end
resetDebugLevel()

----------------------------------------------------------

-- Declare our chat protocol for dissection
local chat_proto = Proto("chat", "SuperFunkyChat Protocol")

----------------------------------------------------------

local function makeValString(enumTable)
    local t = {}
    for name,num in pairs(enumTable) do
        t[num] = name
    end
    return t
end

local command_type = {
    CON_REQUEST   = 0,
    CON_RESPONSE  = 1,
    CON_EXIT      = 2,
    MSG           = 3,
    DIRECT_MSG    = 5,
    LIST_REQUEST  = 6,
    LIST_RESPONSE = 7
}

local command_type_valstr = makeValString(command_type)

----------------------------------------------------------

-- Specify protocol fields
local chat_fields =
{
    length  = ProtoField.uint32("chat.length",  "Length",   base.DEC),
    chksum  = ProtoField.uint32("chat.chksum",  "Checksum", base.HEX),
    command = ProtoField.uint8 ("chat.command", "Command",  base.DEC, command_type_valstr),
    data    = ProtoField.bytes ("chat.data",    "Data"),
}

-- Register the ProtoFields
chat_proto.fields = chat_fields

dprint2("chat_proto ProtoFields registered")

----------------------------------------------------------

-- minimum message size we need to be able to figure out how long the rest is
--  8 because of the `BINX` magic value that gets sent on `CON_REQUEST` messages
local CHAT_MSG_HDR_LEN = 8

local dissectChat, checkChatLength

----------------------------------------------------------

function chat_proto.dissector(buffer, pinfo, tree)
    dprint2("chat_proto.dissector called")

    local pktlen = buffer:len()

    local bytes_consumed = 0

    while bytes_consumed < pktlen do
        -- Call the Chat dissector
        -- Returns:
        --   0 -> error
        --  >0 -> length of the message (if successful)
        --  <0 -> number of additional bytes needed
        local result = dissectChat(buffer, pinfo, tree, bytes_consumed)

        if result > 0 then
            bytes_consumed = bytes_consumed + result
        elseif result == 0 then
            return 0
        else
            -- set `desegment_offset` to how many bytes we already consumed
            pinfo.desegment_offset = bytes_consumed

            -- invert the negative result
            result = -result

            -- set `desegment_len` to how many more bytes we need
            pinfo.desegment_len = result

            return pktlen
        end
    end

    return bytes_consumed
end

----------------------------------------------------------

--  buffer:  A TVB containing packet data
--  start:   The offset in the TVB to read the string from
--  returns: The string and the total length   
function read_string(buffer, start)
    local len = buffer(start, 1):uint()
    local str = buffer(start + 1, len):string()
    
    return str, (len + 1)
end


checkChatLength = function(buffer, offset)
    local msglen = buffer:len() - offset

    if msglen ~= buffer:reported_length_remaining(offset) then
        dprint2("Captured packet was shorter than original, can't reassemble")
        return 0
    end

    if msglen < CHAT_MSG_HDR_LEN then
        dprint2("Need more bytes to figure out the length of the rest of the packet")
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    -- if we got here, we know we have enough bytes to at least
    -- figure out the full length of this Chat message
    local length_tvbr = buffer:range(offset, 4)
    local length_str = length_tvbr:string()

    -- `length` only contains the length of the `type`+`data` portions
    local length_header = 8

    -- if the string `BINX` is contained in the first four bytes
    --  move `length_tvbr` by 4 bytes and add 4 to `length_header` 
    local i, j = string.find(length_str, "BINX")
    if (i) then
        length_tvbr = buffer:range(offset + 4, 4)
        length_header = length_header + 4
    end

    length_val = length_tvbr:uint()

    if msglen < length_val + length_header then
        dprint2("Need more bytes to desegment full Chat message")
        return -(length_val - msglen + length_header)
    end

    return length_val + length_header, length_tvbr
end

-- Dissector function
--  buffer: The packet data as a "Testy Virtual Buffer"
--  pinfo:  Packet information
--  tree:   Root of the UI tree
dissectChat = function(buffer, pinfo, tree, offset)
    dprint2("Chat dissect function called")

    local length_val, length_tvbr = checkChatLength(buffer, offset)

    if length_val <= 0 then
        return length_val
    end

    -- if we got here, we have a whole message in `buffer`

    -- Set the name in the protocol column in the UI
    pinfo.cols.protocol:set("CHAT")

    -- Create sub tree which represents the entire buffer
    local subtree = tree:add(chat_proto, buffer:range(offset, length_val), "SuperFunkyChat Protocol Data")

    -- If the packet contains the magic bytes `BINX`, add 4 to the offset
    local inner_offset = offset

    -- dissect the length field
    local chat_length_tvbr = buffer:range(inner_offset, 4)

    local chat_length_str = chat_length_tvbr:string()
    local i, j = string.find(chat_length_str, "BINX")
    if (i) then
        inner_offset = offset + 4
        chat_length_tvbr = buffer:range(inner_offset, 4)
    end
    
    local chat_length_val = chat_length_tvbr:uint()
    subtree:add(chat_fields.length, chat_length_tvbr)

    -- dissect the checksum field
    local checksum_tvbr = buffer:range(inner_offset + 4, 4)
    subtree:add(chat_fields.chksum, checksum_tvbr)

    -- dissect the command field
    local command_tvbr = buffer:range(inner_offset + 8, 1)
    local command_val = command_tvbr:uint()
    subtree:add(chat_fields.command, command_tvbr)

    -- dissect the data field
    local data = buffer(9):tvb()
    local datatree = subtree:add(chat_fields.data, data())

    if command_val == command_type.MSG then
        local curr_ofs = 0
        local str, len = read_string(data, curr_ofs)
        datatree:add(chat_proto, data(curr_ofs, len), "Username: " .. str)

        curr_ofs = curr_ofs + len
        str, len = read_string(data, curr_ofs)
        datatree:add(chat_proto, data(curr_ofs, len), "Message: " .. str)
    end

    if command_val == command_type.LIST_RESPONSE then
        local curr_ofs = 0
        local user_count = data(curr_ofs, 4):uint()
        datatree:add(chat_proto, data(curr_ofs, 4), "User Count: " .. user_count)
        curr_ofs = curr_ofs + 4
        
        for i=1,user_count do
            local username, username_len = read_string(data, curr_ofs)
            local hostname, hostname_len = read_string(data, curr_ofs + username_len)

            local user_data = data(curr_ofs, username_len + hostname_len):tvb()
            curr_ofs = curr_ofs + username_len
            curr_ofs = curr_ofs + hostname_len

            local usertree = datatree:add('User: ' .. username, user_data())
            usertree:add(chat_proto, user_data(0, username_len), "Username: " .. username)
            usertree:add(chat_proto, user_data(username_len, hostname_len), "Hostname: " .. hostname)
        end
    end

    return length_val
end

----------------------------------------------------------

local function enableDissector()
    DissectorTable.get("tcp.port"):add(default_settings.port, chat_proto)
end

enableDissector()

local function disableDissector()
    DissectorTable.get("tcp.port"):remove(default_settings.port, chat_proto)
end

----------------------------------------------------------

local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

-- register our preferences
chat_proto.prefs.enabled = Pref.bool(
    "Dissector enabled", default_settings.enabled,
    "Whether the SuperFunkyChat dissector is enabled or not"
)

chat_proto.prefs.port = Pref.range(
    "Port", default_settings.port,
    "Port that the SuperFunkyChat Server is using",
    65535
)

chat_proto.prefs.debug = Pref.enum(
    "Debug", default_settings.debug_level,
    "The debug printing level", debug_pref_enum
)

----------------------------------------------------------

-- this function handles preferences being changed
function chat_proto.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level = chat_proto.prefs.debug
    resetDebugLevel()

    if default_settings.port ~= chat_proto.prefs.port then
        -- remove old port, if not 0
        if default_settings.port ~= 0 then
            dprint2("Removing CHAT from old port", default_settings.port)
            DissectorTable.get("tcp.port"):remove(default_settings.port, chat_proto)
        end
        -- set new port
        default_settings.port = chat_proto.prefs.port
        -- add new port, if not 0
        if default_settings.port ~= 0 then
            dprint2("Adding CHAT to new port", default_settings.port)
            DissectorTable.get("tcp.port"):add(default_settings.port, chat_proto)
        end
    end

    if default_settings.enabled ~= chat_proto.prefs.enabled then
        default_settings.enabled = chat_proto.prefs.enabled
        if default_settings.enabled then
            enableDissector()
        else
            disableDissector()
        end
        -- you have to reload the capture file for this type of change
        reload()
    end

end

dprint2("pcapfile Prefs registered")