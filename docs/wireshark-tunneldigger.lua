
tunneldigger = Proto("TD", "Tunneldigger")

local types = { [0] = "INVALID",
		[1] = "COOKIE",
                [2] = "PREPARE",
                [3] = "ERROR",
                [4] = "TUNNEL",
                [5] = "KEEPALIVE",
                [6] = "PMTUD",
                [7] = "PMTUD_ACK",
                [8] = "REL_ACK",
		[9] = "PMTU_NTFY",
                [0xA] = "USAGE",
                [0x80] = "LIMIT"}

local limit_types = { [1] = "BANDWIDTH_DOWN" }

local f_magic1 = ProtoField.uint8("tunneldigger.magic1", "Magic1")
local f_magic2 = ProtoField.uint16("tunneldigger.magic2", "Magic2")
local f_version = ProtoField.uint8("tunneldigger.version", "Version")
local f_type = ProtoField.uint8("tunneldigger.type", "Type", nil, types)
local f_payload_len = ProtoField.uint8("tunneldigger.payload_len", "PayloadLength")
local f_payload = ProtoField.bytes("tunneldigger.payload", "Payload")
local f_padding = ProtoField.bytes("tunneldigger.padding", "Padding")
local f_cookie = ProtoField.bytes("tunneldigger.cookie", "Cookie")
local f_uuid = ProtoField.string("tunneldigger.uuid", "UUID")
local f_uuid_len = ProtoField.uint8("tunneldigger.uuid_len", "Length of UUID")
local f_pmtud = ProtoField.bytes("tunneldigger.pmtud_ack", "Path MTU Discovery Random Data")
local f_pmtud_ack = ProtoField.uint16("tunneldigger.pmtud_ack", "Path MTU Discovery Ack Size")
local f_tunnel_id = ProtoField.uint32("tunneldigger.tunnel_id", "Tunnel ID")
local f_seq_no = ProtoField.uint8("tunneldigger.seq_no", "Sequence Number")
local f_limit_type = ProtoField.uint8("tunneldigger.limit_type", "Type of Limit", nil, limit_types)
local f_limit_bandwidth = ProtoField.uint32("tunneldigger.bandwidth", "Bandwidth")
local f_limit_bandwidth_len = ProtoField.uint8("tunneldigger.bandwidth_len", "Length of Bandwidth")
local f_usage = ProtoField.uint8("tunneldigger.usage", "Usage of Server")
tunneldigger.fields = { f_magic1, f_magic2, f_version, f_type, f_payload_len, f_payload, f_padding, f_cookie, f_pmtud, f_pmtud_ack, f_uuid_len, f_uuid, f_tunnel_id, f_seq_no, f_limit_type, f_limit_bandwidth, f_limit_bandwidth_len, f_usage}


function tunneldigger.dissector(buffer, pinfo, tree)

  local type_detail = {}
  type_detail["COOKIE"]    = {}
  type_detail["PREPARE"]   = 0x02
  type_detail["SCANRESP"] = {[0] = "mac", [1] = "data", [2]="flag"}
  type_detail["ERROR"]     = 0x03
  type_detail["TUNNEL"]    = 0x04
  type_detail["KEEPALIVE"] = 0x05
  type_detail["PMTUD"]     = 0x06
  type_detail["PMTUD_ACK"] = 0x07
  type_detail["REL_ACK"]   = 0x08
  type_detail["PMTU_NTFY"] = 0x09
  type_detail["USAGE"]     = 0x0A

  --- check if header is to small
  if buffer:len() < 6 then
    return
  end

  local l2tp_type = buffer(0, 1):uint()
  local td_type = buffer(4, 1):uint()
  local payload_len = buffer(5, 1):uint()

  if l2tp_type ~= 0x80 then
    -- give it to l2tp
    local udp_table = DissectorTable.get("udp.port")
    local l2tp_dis = udp_table:get_dissector(1701)
    l2tp_dis:call(buffer, pinfo, tree)
    return
  end

  pinfo.cols.protocol = "TD"

  local subtree = tree:add(tunneldigger, buffer(), "Tunneldigger")
  subtree:add(f_magic1, buffer(0, 1))
  subtree:add(f_magic2, buffer(1, 2))
  subtree:add(f_version, buffer(3, 1))
  subtree:add(f_type, buffer(4, 1))
  subtree:add(f_payload_len, buffer(5, 1))

  if buffer:len() < (6 + payload_len) then
    pinfo.cols.info = string.format("%s - Package too small.", types[td_type])
    return
  else
    pinfo.cols.info = types[td_type]
  end

  local detail = type_detail[types[td_type]]
  if types[td_type] == "COOKIE" then
    subtree:add(f_cookie, buffer(6, 8))
  elseif types[td_type] == "PMTUD" then
    subtree:add(f_pmtud, buffer(6, payload_len))
  elseif types[td_type] == "PMTUD_ACK" then
    subtree:add(f_pmtud_ack, buffer(6, 2))
  elseif types[td_type] == "PREPARE" then
    local uuid_len = buffer(14, 1):uint()
    subtree:add(f_cookie, buffer(6, 8))
    subtree:add(f_uuid_len, buffer(14, 1))
    subtree:add(f_uuid, buffer(15, uuid_len))
  elseif types[td_type] == "TUNNEL" then
    subtree:add(f_tunnel_id, buffer(6, 4))
  elseif types[td_type] == "USAGE" then
    subtree:add(f_usage, buffer(6, 2))
  elseif types[td_type] == "LIMIT" then
    --- seq no comes from RELIABLE_MESSAGE
    subtree:add(f_seq_no, buffer(6, 2))
    subtree:add(f_limit_type, buffer(8, 1))
    if limit_types[buffer(8, 1):uint()] == "BANDWIDTH_DOWN" then
      subtree:add(f_limit_bandwidth_len, buffer(9, 1))
      --- Bandwidth should be always 4 byte long
      --- TODO: add a warning here
      subtree:add(f_limit_bandwidth, buffer(10, 4))
      pinfo.cols.info = string.format("%s to %d kbps", pinfo.cols.info, buffer(10, 4):uint())
    end
  else
    if payload_len > 0 then
      subtree:add(f_payload, buffer(6, payload_len))
    end
  end

  if buffer:len() > (6 + payload_len) then
    subtree:add(f_padding, buffer(6 + payload_len, buffer:len() - (6 + payload_len)))
  end
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(8942, tunneldigger)
