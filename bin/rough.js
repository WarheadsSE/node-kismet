var Kismet = require('../lib/kismet.js')

var k = new Kismet()

// only a "connect" event, not ready until "ready"
k.on('connect',function(){
    console.log('connected!')
})

// this is "ready"
k.on('ready',function(){
    console.log('ready!')
    
    this.subscribe('bssid'
        , ['bssid','manuf','channel','type']
        , function(had_error,message){
            console.log('bssid - '+ message)
        }
    )
    this.subscribe('ssid'
        , ['ssid','mac','cryptset','type','packets']
        , function(had_error,message){
            console.log('ssid - '+ message)
    })
    this.subscribe('client'
        , ['bssid','mac','type']
        , function(had_error,message){
            console.log('client - '+ message)
    })
    
    /* 
    // output all known sentences & fields
    console.log('protocols:')
    console.log(k.protocols)
    for( var i=0; i<k.protocols.length; i++){
        k.command('CAPABILITY '+ k.protocols[i])
    }
    */
})


/*
k.on('rawData',function(rawData){ 
    console.log('raw:'+rawData)
})
*/

k.on('CAPABILITY',function(fields){
    console.log('capability:' + fields.protocol)
    console.log(fields.fields.split(','))
})


k.on('BSSID',function(fields){
    console.log(
        'Kismet sees bssid : ' + fields.bssid
        + ' type: ' + k.types.lookup('network',fields.type)
        + ' manuf: ' + fields.manuf
        + ' channel: ' + fields.channel
    )
})

k.on('SSID',function(fields){
    if( fields.packets > 1 ){
        console.log(
            'Kismet sees ssid  : ' + fields.mac
            + ' type: ' + k.types.lookup('ssid',fields.type)
            + ' ssid: ' + fields.ssid
            + ' pkts: ' + fields.packets
            + ' cryptset: ' + fields.cryptset
        )
    }
})

k.on('CLIENT',function(fields){
    if( fields.bssid != fields.mac ){
        console.log(
            'Kismet sees client: ' + fields.bssid
            + ' type: ' + k.types.lookup('client',fields.type)
            + ' mac: ' + fields.mac
        )
    }
})

k.on('TIME',function(fields){
    console.log(new Date(fields.time*1000))
})

k.on('error',function(error){
    console.log('kismet had an error: '+ error.code)
})

k.on('end', function(){
    console.log('kismet disconnected')
})

k.connect()
/*
setTimeout(function(){ 
    k.unsubscribe('bssid')
    k.unsubscribe('ssid')
    
    setTimeout(function(){
        k.disconnect() 
    },1*1000)
}, 30*1000)
*/
