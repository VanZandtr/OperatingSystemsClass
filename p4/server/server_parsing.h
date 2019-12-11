#pragma once

#include "server_storage.h"

/// When a new client connection is accepted, this code will run to figure out
/// what the client is requesting, and to dispatch to the right function for
/// satisfying the request.
///
/// @param sd      The socket on which communication with the client takes place
/// @param pri     The private key used by the server
/// @param pub     The public key file contents, to send to the client
/// @param storage The Storage object with which clients interact
///
/// @returns true if the server should halt immediately, false otherwise
bool serve_client(int sd, RSA *pri, const vec &pub, Storage &storage);
