var express = require('express')
var app = express();
var http = require('http').Server(app);
var client_io = require('socket.io')(http);

var port = process.argv[2] || 3003
var coordination_server = process.argv[3] || 'http://localhost:3001'

var crypto = require('crypto')

var clients = []
var private_keys = []
var public_keys = []

/////////////////////////////////////////////////////////////////////////////
// web client IO
client_io.on('connection', function (client) {

  // the id of the browser
  var id = client.id
  clients.push(client)

  console.log('a user connected', id, 'generating keys')

  // generate a key object for the client
  var keypair = crypto.getDiffieHellman('modp14')

  // generate the keys
  keypair.generateKeys()

  // add to list of private keys
  private_keys.push({
    id: id,
    keypair: keypair
  })

  // add hex text of publickey to list of public keys
  public_keys.push({
    id: id,
    publickey: keypair.getPublicKey('hex')
  })

  // send the fresh public key to the key server
  server_socket.emit('new_keypair', {
    id: id,
    publickey: keypair.getPublicKey('hex')
  })

  client.on('chat_message', function (msg) {
    // browser sent a chat message
    // encrypt the message for everyone in the public keys, and fire them off to
    // the server_socket as 'chat_message' events

    console.log('incoming chat message from browser', msg)

    var from_keypair

    private_keys.forEach(function (key) {
      if (key.id.indexOf(msg.from) !== -1) {
        console.log('found keypair')
        from_keypair = key.keypair
      }
    })
    if (from_keypair === undefined) {
      return;
    }

    if (msg.to === 'all') {
      console.log('broadcasting to all')

      // for every user we have a public key for
      public_keys.forEach(function (key) {

        // calculate the shared secret
        var shared_secret = from_keypair.computeSecret(key.publickey, 'hex', 'hex')

        // create 256 bit hash of the shared secret to use as the AES key
        var password = crypto.createHash('sha256').update(shared_secret).digest()

        // encrypt the message using the hash of the shared secret as the password
        var cipher = crypto.createCipher('aes256', password)

        // create the ciphertext using the encryption object
        var cipher_text = Buffer.concat([cipher.update(msg.msg), cipher.final()])

        var encrypted_msg = {
          from: msg.from,
          to: key.id,
          msg: cipher_text.toString('hex')
        }

        server_socket.emit('chat_message', encrypted_msg)
      })
    }

    //
  })

  client.on('disconnect', function () {

    server_socket.emit('remove_keypair', {
      id: client.id.split('/#')[1]
    })

    clients = clients.filter(function (c) {
      return c !== client
    })
    console.log('socket disconnected', clients.length, 'clients remaining.')
  })
});

// Connect to server
var server_io = require('socket.io-client');
var server_socket = server_io.connect(coordination_server, {
  reconnect: true
});

// Add a connect listener
server_socket.on('connect', function () {
  console.log('Connected to server.');
  // request keypairs
});

server_socket.on('key_cleanup', function (msg) {
  // server is asking for the client to send all the public keys it has
  // private keys for, that are also current connected clients
  var current_client_ids = []
  clients.forEach(function (c) {
    current_client_ids.push(c.id)
  })
  var new_private_keys = []
  private_keys.forEach(function (key) {
    if (current_client_ids.indexOf(key.id) !== -1) {
      new_private_keys.push(key)
    }
  })

  private_keys = new_private_keys

  var public_key_ids = []
  public_keys.forEach(function (k) {
    public_key_ids.push(k.id)
  })

  var msg = {
    keys: []
  }
  private_keys.forEach(function (key) {
    msg.keys.push({
      id: key.id,
      publickey: key.keypair.getPublicKey('hex')
    })
  })

  // send all the keys to the server
  server_socket.emit('allkeys', msg)

})

server_socket.on('broadcast_public_keys', function (msg) {
  public_keys = msg
})

server_socket.on('new_keypair', function (msg) {
  // add keypair to keys

  // console.log(msg.id)

  console.log('got a new keypair')
  if (public_keys.filter(function (k) {
      return k.id === msg.id
    }).length === 0) {
    console.log('not found in list of publickeys, adding to list')
    public_keys.push(msg)
  } 
})
server_socket.on('remove_keypair', function (msg) {
  console.log('got remove keypair event ')
    // remove key from keys where msg.id = key[n].id
  console.log('length before', public_keys.length)
  public_keys = public_keys.filter(function (k) {
    return k.id !== msg.id
  })
  console.log('length after', public_keys.length)
  console.log()
})
server_socket.on('chat_message', function (msg) {
  // incoming chat message from the server
  // { to: id, from: id, data: '...' }
  // find the privatekey for the to_id
  // find the publickey for the from_id
  // decrypt the message
  // emit the decrypted message to the client with the matching to_id

  console.log('got an encrypted message from the server')
  console.log(msg.to, msg.from)

  var keyA = find_key(msg.to)
  var keyB = find_key(msg.from)

  // console.log(keyA.type, keyB.type)

  var private_key_obj, public_key_hex

  if (keyA.type === 'private' && keyB.type === 'public') {
    private_key_obj = keyA.key.keypair
    public_key_hex = keyB.key.publickey
  } else if (keyA.type === 'public' && keyB.type === 'private') {
    private_key_obj = keyB.key.keypair
    public_key_hex = keyA.key.publickey
  } else if (keyA.type === 'private' && keyB.type === 'private') {
    private_key_obj = keyA.key.keypair
    public_key_hex = keyB.key.keypair.getPublicKey('hex')
  } else {
    return console.log('no private key found for message, moving on...')
  }

  var shared_secret = private_key_obj.computeSecret(public_key_hex, 'hex', 'hex')

  // create 256 bit hash of the shared secret to use as the AES key
  var password = crypto.createHash('sha256').update(shared_secret).digest()

  // encrypt
  var decipher = crypto.createDecipher('aes256', password)
  var plain_text = Buffer.concat([decipher.update(Buffer(msg.msg, 'hex')), decipher.final()])

  var decrypted_msg = {
    from: msg.from,
    to: msg.to,
    msg: plain_text.toString()
  }

  console.log('decrypted_message', decrypted_msg)

  // send message to the client with the id of msg.to
  clients.forEach(function (client) {
    if (client.id.indexOf(msg.to) !== -1) {
      console.log('sending message to browser')
      client.emit('decrypted_message', decrypted_msg)
    }
  })
  return;
})

function find_key(id) {
  var keyfound = false
  var returnkey
  var type

  private_keys.forEach(function (key) {
    if (key.id.indexOf(id) !== -1) {
      keyfound = true
      returnkey = key
      type = 'private'
    }
  })

  if (!keyfound) {
    public_keys.forEach(function (key) {
      if (key.id.indexOf(id) !== -1) {
        // console.log('here', key)
        keyfound = true
        returnkey = key
        type = 'public'
      }
    })
  }

  if (keyfound) {
    return {
      search_id: id,
      key: returnkey,
      type: type
    }
  } else {
    return -1
  }

}


app.use(express.static('public'))

http.listen(port, function () {
  console.log('listening on *:' + port);
});