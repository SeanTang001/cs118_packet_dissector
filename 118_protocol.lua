-- declare protocol
secure_protocol = Proto("CS118_Secure",  "Security layer of CS118 protocol")
-- Secure Header
secure_msg_type = ProtoField.uint8("secure.msg_type", "msg_type", base.DEC)
secure_msg_len = ProtoField.uint16("secure.msg_len", "msg_len", base.DEC)
-- Secure Certificate
cert_key_length  = ProtoField.uint16("secure.cert.key_length", "key_length", base.DEC)
cert_pub_key  = ProtoField.bytes("secure.cert.pub_key", "pub_key", base.SPACE)
cert_sig  = ProtoField.bytes("secure.cert.sig", "sig", base.SPACE)
-- Secure Client Hello
client_hello_comm_type = ProtoField.uint8("secure.clienthello.commtype", "commtype", base.DEC)
client_hello_nonce = ProtoField.bytes("secure.clienthello.client_nonce", "client_nonce", base.SPACE)
-- Secure Server Hello
server_hello_type = ProtoField.uint8("secure.serverhello.commtype", "comm_type", base.DEC)
server_hello_sigsize = ProtoField.uint8("secure.serverhello.sigsize", "sig_size", base.DEC)
server_hello_certsize = ProtoField.uint16("secure.serverhello.certsize", "cert_size", base.DEC)
server_hello_server_nonce = ProtoField.bytes("secure.serverhello.server_nonce", "server_nonce", base.SPACE)
server_hello_client_nonce_sig = ProtoField.bytes("secure.serverhello.client_nonce_sig", "client_nonce_sig", base.SPACE)
-- Secure Key Exchange Request
key_exchange_sigsize = ProtoField.uint8("secure.keyexchange.sigsize", "sig_size", base.DEC)
key_exchange_certsize = ProtoField.uint16("secure.keyexchange.certsize", "cert_size", base.DEC)
key_exchange_server_nonce_sig = ProtoField.bytes("secure.keyexchange.server_nonce_sig", "server_nonce_sig", base.SPACE)
-- Secure Data
data_payload_size = ProtoField.uint16("secure.data.payloadsize", "payload_size", base.DEC)
data_IV = ProtoField.bytes("secure.data.IV", "IV", base.SPACE)
data_encrypted_payload = ProtoField.bytes("secure.data.encrypted_payload", "encrypted_payload", base.SPACE)
data_MAC = ProtoField.bytes("secure.data.MAC", "MAC", base.SPACE)

secure_protocol.fields = {
    secure_msg_type, 
    secure_msg_len, 
    cert_key_length,
    cert_pub_key,
    cert_sig,
    client_hello_comm_type,
    client_hello_nonce,
    server_hello_type,
    server_hello_sigsize,
    server_hello_certsize,
    server_hello_server_nonce,
    server_hello_client_nonce_sig,
    key_exchange_sigsize,
    key_exchange_certsize,
    key_exchange_server_nonce_sig,
    data_payload_size,
    data_IV,
    data_encrypted_payload,
    data_MAC
}

function certficate_dissector(buffer, pinfo, tree)
    -- retrieve buffer length
    length = buffer:len()
    -- filter empty packets
    if length < 8 then
        return
    end
    -- Set protocol name
    pinfo.cols.protocol = secure_protocol.name
    -- Add protocol to tree
    local subtree = tree:add(secure_protocol, buffer(), "Certificate")

    subtree:add(cert_key_length, buffer(0, 2))
    subtree:add(cert_pub_key, buffer(4, buffer(0,2):uint()))
    subtree:add(cert_sig, buffer(4+buffer(0,2):uint(), length-(4+buffer(0,2):uint())))
end

function data_dissector(buffer, pinfo, tree)
    -- retrieve buffer length
    length = buffer:len()
    -- filter empty packets
    if length == 0 then
        return
    end
    -- Set protocol name
    pinfo.cols.protocol = secure_protocol.name
    -- Add protocol to tree
    local subtree = tree:add(secure_protocol, buffer(), "Data")

    subtree:add(data_payload_size, buffer(0, 2))
    subtree:add(data_IV, buffer(4, 16))
    subtree:add(data_encrypted_payload, buffer(20, buffer(0,2):uint()))
    if length > 20+buffer(0,2):uint()+32 then
        return
    end
    subtree:add(data_MAC, buffer(20+buffer(0,2):uint(), 32))
end

function key_exchange_request_dissector(buffer, pinfo, tree)
    -- retrieve buffer length
    length = buffer:len()
    -- filter empty packets
    if length == 0 then
        return
    end
    -- Set protocol name
    pinfo.cols.protocol = secure_protocol.name
    -- Add protocol to tree
    local subtree = tree:add(secure_protocol, buffer(), "Key Exchange Request")

    subtree:add(key_exchange_sigsize, buffer(1, 1))
    subtree:add(key_exchange_certsize, buffer(2, 2))
    certficate_dissector(buffer(4, buffer(2,2):uint()), pinfo, subtree)
    subtree:add(key_exchange_server_nonce_sig, buffer(4+buffer(2,2):uint(), buffer(1,1):uint()))
end


function server_hello_dissector(buffer, pinfo, tree)
    -- retrieve buffer length
    length = buffer:len()
    -- filter empty packets
    if length == 0 then
        return
    end
    -- Set protocol name
    pinfo.cols.protocol = secure_protocol.name
    -- Add protocol to tree
    local subtree = tree:add(secure_protocol, buffer(), "Server Hello")

    subtree:add(server_hello_type, buffer(0, 1))
    subtree:add(server_hello_sigsize, buffer(1, 1))
    subtree:add(server_hello_certsize, buffer(2, 2))
    subtree:add(server_hello_server_nonce, buffer(4, 32))
    certficate_dissector(buffer(36, buffer(2,2):uint()), pinfo, subtree)
    subtree:add(server_hello_client_nonce_sig, buffer(36+buffer(2,2):uint(), buffer(1,1):uint()))
end

function client_hello_dissector(buffer, pinfo, tree)
    -- retrieve buffer length
    length = buffer:len()
    -- filter empty packets
    if length == 0 then
        return
    end
    -- Set protocol name
    pinfo.cols.protocol = secure_protocol.name
    -- Add protocol to tree
    local subtree = tree:add(secure_protocol, buffer(), "Client Hello")

    subtree:add(client_hello_comm_type, buffer(0, 1))
    subtree:add(client_hello_nonce, buffer(4, 32))
end

function secure_protocol_dissector(buffer, pinfo, tree)
    -- retrieve buffer length
    length = buffer:len()
    -- filter empty packets
    if length == 0 then
        return
    end
    -- Set protocol name
    pinfo.cols.protocol = secure_protocol.name
    -- Add protocol to tree
    local subtree = tree:add(secure_protocol, buffer(), "Secure Protocol")

    local msgtype = tonumber(buffer(0,1):uint())
    print(msgtype)
    
    subtree:add(secure_msg_type, buffer(0, 1))
    subtree:add(secure_msg_len, buffer(2, 2))

    -- client_hello_dissector(buffer(2,length-2),pinfo,tree)

    if msgtype == 1 then
        print("1 found !")
        client_hello_dissector(buffer(4,length-4),pinfo,subtree)
    end
    if msgtype == 2 then
        print("2 found !")
        server_hello_dissector(buffer(4,length-4),pinfo,subtree)
    end
    if msgtype == 16 then
        print("16 found !")
        key_exchange_request_dissector(buffer(4,length-4),pinfo,subtree)
    end
    if msgtype == 20 then
        subtree:add(secure_protocol, buffer(), "Finished")
    end
    if msgtype == 255 then
        print("255 found !")
        data_dissector(buffer(4,length-4),pinfo,subtree)
    end

    -- Add fields to tree
end


-- declare protocol
simple_protocol = Proto("CS118_No_Security",  "No security variation of CS118 protocol")
-- declare fields
packet_number = ProtoField.uint32("transport.packet_number", "packet_number", base.DEC)
acknowledgment_number = ProtoField.uint32("transport.acknowledgment_number", "acknowledgment_number", base.DEC)
payload_size = ProtoField.uint16("transport.payload_size", "payload_size", base.DEC)
payload_byte = ProtoField.bytes("transport.payload_byte", "payload_byte", base.SPACE)
payload_str = ProtoField.string("transport.payload_str", "payload_str")
simple_protocol.fields = { packet_number, acknowledgment_number, payload_size, payload_byte, payload_str }
function simple_protocol.dissector(buffer, pinfo, tree)
    -- retrieve buffer length
    length = buffer:len()
    -- filter empty packets
    if length == 0 then
        return
    end
    -- Set protocol name
    pinfo.cols.protocol = simple_protocol.name
    -- Add protocol to tree
    local subtree = tree:add(simple_protocol, buffer(), "Reliable Transport Protocol")
    -- Add fields to tree
    subtree:add(packet_number, buffer(0, 4))
    subtree:add(acknowledgment_number, buffer(4, 4))
    subtree:add(payload_size, buffer(8, 2))
    subtree:add(payload_byte, buffer(12, length - 12)) -- Remove header
    subtree:add(payload_str, buffer(12, length - 12)) -- Remove header
    if buffer:range(8, 2):uint() == 0 then
        return
    end
    secure_protocol_dissector(buffer(12,length-12),pinfo, tree)
end
-- Match protocol by UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(8080, simple_protocol)