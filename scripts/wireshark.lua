local opengal_proto = Proto("opengal_proto","OpenGAL Protocol")

local length_field = ProtoField.uint32("opengal_proto.len", "Length", base.DEC)

opengal_proto.fields = { length_field }


function opengal_proto.dissector(tvbuf, pkt_info, root)
    if tvbuf(0, 1):uint() == 0x01 then
        pkt_info.cols.dst:set("Headunit")
    else
        pkt_info.cols.dst:set("Mobile Device")
    end
    pkt_info.cols.protocol:set("Android Auto")
end

local null_dissector = DissectorTable.get("null.type")
null_dissector:add(0x00, opengal_proto)