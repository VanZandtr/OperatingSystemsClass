#pragma once

#include "../common/crypto.h"

#include "server_storage.h"

/// Respond to an ALL command by generating a list of all the usernames in the
/// Auth table and returning them, one per line.
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_all(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req);

/// Respond to a SET command by putting the provided data into the Auth table
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_set(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req);

/// Respond to a GET command by getting the data for a user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_get(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req);

/// Respond to a REG command by trying to add a new user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_reg(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req);

/// In response to a request for a key, do a reliable send of the contents of
/// the pubfile
///
/// @param sd The socket on which to write the pubfile
/// @param pubfile A vector consisting of pubfile contents
void server_cmd_key(int sd, const vec &pubfile);

/// Respond to a BYE command by returning false, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns true, to indicate that the server should stop, or false on an error
bool server_cmd_bye(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req);

/// Respond to a SAV command by persisting the file, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_sav(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req);
