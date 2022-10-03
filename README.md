
![Chatroom window](screenshot.png?raw=true)

### usage

```bash
# clone repo
https://github.com/harshasingamshetty1/Socket.io-Encrypted-Chat.git
cd Socket.io-Encrypted-Chat
npm install

# starting the coordination server
# the first argument is the port
node server.js 3001

# starting the local proxy server
# the first argument is the port
# the second argument is the address and port of the coordinator server
node crypto-proxy.js 3003 http://localhost:3001

# open the browser to connect to the local proxy.
# now we can open multiple tabs and chat securely!
open http://localhost:3003
```