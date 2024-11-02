const TCPClientInterface = require("./src/interfaces/tcp_client_interface");

// connect to rns tcp server
// const client = new TCPClientInterface("Server 1", "amsterdam.connect.reticulum.network", 4965);
// const client = new TCPClientInterface("Server 2", "reticulum.betweentheborders.com", 4242);
const client = new TCPClientInterface("Server 3", "v0lttech.com", 4242);
client.connect();
