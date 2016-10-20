/* kismet-node
 * nodejs implementation of the kisment client/server api
 * http://www.kismetwireless.net/documentation.shtml #16
 * inspired by the ruby scripts, part of kismet
 */

var net = require('net')
    , util = require('util')
    , events = require('events')

// Enums explicitly defined for the ease of client writers
var types = Object.freeze({
    network : {
        ap : 0
	    , adhoc : 1
    	, probe : 2
    	, turbocell : 3
    	, data : 4
    	, mixed : 255
    	, remove : 256
    },
    client : {
        unknown : 0
    	, fromds : 1
    	, tods : 2
    	, interds : 3
    	, established : 4
    	, adhoc : 5
	    , remove : 6
    },
    ssid : {
        beacon : 0
    	, proberesp : 1
    	, probereq : 2
    	, file : 3
    },
    lookup : function(name,type){
        var ret = undefined
        if( types.hasOwnProperty(name) ){
            for(var i in types[name])
            if( types[name].hasOwnProperty(i) ){
                if( types[name][i] == type){
                    ret = i
                    break;
                }
            }
        }
        return ret
    }
});

// Crypt bitfield
var crypt_types = Object.freeze({
    crypt_none : 0,
	crypt_unknown : 1,
	crypt_wep : (1 << 1),
	crypt_layer3 : (1 << 2),
	// Derived from WPA headers
	crypt_wep40 : (1 << 3),
	crypt_wep104 : (1 << 4),
	crypt_tkip : (1 << 5),
	crypt_wpa : (1 << 6),
	crypt_psk : (1 << 7),
	crypt_aes_ocb : (1 << 8),
	crypt_aes_ccm : (1 << 9),
	//WPA Migration Mode
	crypt_wpa_migmode : (1 << 19),
	// Derived from data traffic
	crypt_leap : (1 << 10),
	crypt_ttls : (1 << 11),
	crypt_tls : (1 << 12),
	crypt_peap : (1 << 13),
	crypt_isakmp : (1 << 14),
    crypt_pptp : (1 << 15),
	crypt_fortress : (1 << 16),
	crypt_keyguard : (1 << 17),
	crypt_unknown_nonwep : (1 << 18),
});

// translate a lookup of cryptset
var crypt_to_str = function(cryptset) {
    var osstr = '';

	if (cryptset == 0)
		osstr += "None (Open)";
	if (cryptset == crypt_types.crypt_wep)
		osstr += "WEP (Privacy bit set)";
	if (cryptset & crypt_types.crypt_layer3)
		osstr += " Layer3";
	if (cryptset & crypt_types.crypt_wpa_migmode)
		osstr += " WPA Migration Mode";
	if (cryptset & crypt_types.crypt_wep40)
		osstr += " WEP (40bit)";
	if (cryptset & crypt_types.crypt_wep104)
		osstr += " WEP (104bit)";
	if (cryptset & crypt_types.crypt_wpa)
		osstr += " WPA";
	if (cryptset & crypt_types.crypt_tkip)
		osstr += " TKIP";
	if (cryptset & crypt_types.crypt_psk)
		osstr += " PSK";
	if (cryptset & crypt_types.crypt_aes_ocb)
		osstr += " AES-ECB";
	if (cryptset & crypt_types.crypt_aes_ccm)
		osstr += " AES-CCM";
	if (cryptset & crypt_types.crypt_leap)
		osstr += " LEAP";
	if (cryptset & crypt_types.crypt_ttls)
		osstr += " TTLS";
	if (cryptset & crypt_types.crypt_tls)
		osstr += " TLS";
	if (cryptset & crypt_types.crypt_peap)
		osstr += " PEAP";
	if (cryptset & crypt_types.crypt_isakmp)
		osstr += " ISA-KMP";
	if (cryptset & crypt_types.crypt_pptp)
		osstr += " PPTP";
	if (cryptset & crypt_types.crypt_fortress)
		osstr += " Fortress";
	if (cryptset & crypt_types.crypt_keyguard)
		osstr += " Keyguard";
	if (cryptset & crypt_types.crypt_unknown_nonwep)
		osstr += " WPA/ExtIV data";

    // remove first space
    if( osstr.substr(0,1) == ' ' )
        osstr = osstr.slice(1)
	return osstr;
}





// new/initializer
function Kismet(host,port,sourceAddress) {
    this.host = host || 'localhost'
    this.port = port || 2501
    this.sourceAddress = sourceAddress || '127.0.0.1'
    
    this.socket = undefined
    var self = this
    this.commandCount = 1
    this.commandAck = {}
    this.commands = {
        KISMET: {
            fields: ['version','starttime','servername','dumpfiles','uid']
            , fixed: true
            , listeners: -1
            , callback: undefined
        },
        PROTOCOLS: {
            fields: ['protocols']
            , fixed: true
            , listeners: -1
            , callback: function(fields){
                self.protocols = fields.protocols.split(',')
                self.emit('ready')
            }
        },
        CAPABILITY: {
            fields: ['protocol','fields']
            , fixed: true
            , listeners: -1
            , callback: function(fields){
                var availableFields = fields.fields.split(',')
                fields.fields.protocol = fields.fields.protocol.toUpperCase()
                if( !self.commands[fields.protocol].fixed ){
                    self.commands[fields.protocol].availableFields = availableFields
                }
            }
        },
        TIME: {
            fields: ['time']
            , fixed: true
            , listeners: -1
            , callback: undefined
        },
        ACK: {
            fields: ['id','message']
            , fixed: true
            , listeners: -1
            , callback: function(fields){
                self.handleAckError('ACK',fields)
            }
        },
        ERROR: {
            fields: ['id','message']
            , fixed: true
            , listeners: -1
            , callback: function(fields){
                self.handleAckError('ERROR',fields)
            }
        },
        TERMINATE: {
            fields: ['message']
            , fixed: true
            , listeners: -1
            , callback: undefined
        },
    }
    this.protocols = []
    this.buffer = ''
    
    this.types = types
    this.crypt_types = crypt_types
    this.crypt_to_str = crypt_to_str
    
    events.EventEmitter.call(this)
}
util.inherits(Kismet, events.EventEmitter);
module.exports = Kismet

// handleAckError - handle issuance of ackback calls.
// -- signature of ackback is f(error: boolean, message: string)
Kismet.prototype.handleAckError = function (cmd,fields){
    if( this.commandAck[fields.id] instanceof Function ){
        this.commandAck[fields.id]((cmd!='ACK'),fields.message)
    }
}

// connect - form the connection
Kismet.prototype.connect = function(){
    var self = this
    if( !this.socket ){
        this.socket = net.connect({
                host: this.host, 
                port: this.port, 
                localAddress: this.sourceAddress
            },
            function(){
                // protocol is ascii
                self.socket.setEncoding('ascii')
                // emit \010 to init
                self.socket.write('\n')
                // let the callee know we're online
                self.emit('connect')
            }
        )
        this.socket.on('data',function(data){
            data = data.toString()
            self.bufferData(data)
            self.emit('rawData',data)
        })
        this.socket.on('end',function(){
            self.emit('end')
        })
        this.socket.on('error',function(error){
            self.emit('error',error)
        })
    }
}
// close the connection, if open
Kismet.prototype.disconnect = function(){
    if( this.socket ){
        this.socket.end()
    }
}

// bufferData - buffer the data, in the event it doesn't have complete sentences
// in one packet
Kismet.prototype.bufferData = function(data){
    var self, i, lines
    
    this.buffer+=data
    lines = this.buffer.split('\n')
    for(i=0; i<lines.length; i++){
        if( i+1 == lines.length ){
            if( lines[i] != '' ){ 
                // remnants
                this.buffer = lines[i]
            }else{
                // no remnants
                this.buffer = ''
            }
        }else{
            if( lines[i] != ''){
                this.parseLine(lines[i])
            }
        }
    }
}

// sendRaw - send raw text, in ascii, with \n for good measure
Kismet.prototype.sendRaw = function(rawText){
    this.socket.write(rawText+"\n",'ascii')
}

// parseLine - parse each line
Kismet.prototype.parseLine = function(line){
    var pattern = /^\*([A-Z0-9]+): (.*)/
        , result
        , fields
    result = pattern.exec(line)
    // if result (!null,as null is pattern failure)
    if( Array.isArray(result) ){
        /* result is array. 
         * 0 = matched (meaning line)
         * 1 = protcol/sentence
         * 2 = fields
         */
         fields = this.parseData(result[1],result[2])
         // if protocol registered
         if( this.commands[result[1]] ){
            // if callback was set, do that first
            if( this.commands[result[1]].callback instanceof Function){
                this.commands[result[1]].callback(fields)
            }
            // emit the event
            this.emit(result[1],fields)
         }
    }
}

// parseData - parse the fields of each sentence
Kismet.prototype.parseData = function(protocol,data){
    //console.log('kistmet:parseData:'+protocol+':'+data)
    var inDelimiter = false
        , i = 0
        , fieldNumber = 0
        , field = ''
        , obj = {}
    for( i=0; i<data.length; i++){
        if( data[i] == '\001'){
            inDelimiter = !inDelimiter
        }else if( (data[i] == ' ' && !inDelimiter) ){
            obj[this.commands[protocol].fields[fieldNumber]]=field
            fieldNumber++
            field=''
        }else{
            field+=data[i]
        }
    }
    // catch straggling bits
    obj[this.commands[protocol].fields[fieldNumber]]=field
    
    return obj
    
}

// subscribe - receive PROTCOL sentences, with FIELDS
Kismet.prototype.subscribe = function(protocol,fields,ackback,callback){
    var cmd = -1
        , f
    protocol = protocol.toUpperCase()
    if( this.protocols.indexOf(protocol) > -1 && Array.isArray(fields) ){
        // make sure we're not stomping a fixed.
        if( this.commands[protocol] != undefined ){
            if( this.commands[protocol].fixed ){
                return cmd
            }
        }
        
        // lowercase all the fields
        for(f=0; f<fields.length; f++){
            fields[f] = fields[f].toLowerCase()
        }
        
        // if we are not the first, walk it to add the fields
        if( this.commands[protocol] != undefined ){
            // foreach existing, see if it is in the new.
            var i, j, hit = false
            for( i=0; i<this.commands[protocol].fields.length; i++){
                for( j=0; j<fields.length; j++){
                    if( this.commands[protocol].fields[i] == fields[j] ){
                        hit = true
                        break;
                    }
                }
                // if this item is not in the new fields list, add it
                if( !hit ){
                    fields.push(this.commands[protocol].fields[i])
                }
            }
        }
        
        
        
        cmd = this.commandCount++
        this.sendRaw(
            '!' + cmd
            + ' ENABLE'
            + ' ' + protocol
            + ' ' + fields.join(',')
        )
        
        if( this.commands[protocol] != undefined ){
            this.commands[protocol].fields = fields
            this.commands[protocol].listeners++ 
        }else{
            this.commands[protocol]={
                fields: fields
                , callback: callback
                , listeners: 1
                , fixed: false
            }
        }
        if( ackback instanceof Function ){
            this.commandAck[cmd]=ackback
        }
    }
    return cmd
}

// unsubscribe - stop receiving PROTOCOL sentenees
Kismet.prototype.unsubscribe = function(protocol,ackback){
    var cmd = -1
    protocol = protocol.toUpperCase()
    // protocol must exist, and have been setup
    if( this.protocols.indexOf(protocol) > -1 
        && this.commands[protocol] != undefined ){
        // don't remove fixed, or where listeners != 1 (last)
        if( this.commands[protocol].listeners == 1 
            && !this.commands[protocol].fixed ){
            cmd = this.commandCount++
            this.sendRaw(
                '!' + cmd
                + ' REMOVE'
                + ' ' + protocol
            )
            if( ackback instanceof Function ){
                this.commandAck[cmd]=ackback
            }  
        }else{
            this.commands[protocol].listeners--
        }
    }
    return cmd
}

// command - send raw command. 
// -- Use with extreme caution
Kismet.prototype.command = function(command,ackback){
    var cmd = this.commandCount++
    this.sendRaw(
        '!' + cmd
        + ' ' + command
    )
    if( ackback instanceof Function ){
        this.commandAck[cmd]=ackback
    }
    return cmd
}
