#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <sstream>
#include <openssl/rsa.h>
#include <string>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "client_commands.h"

using namespace std;

//declare helper functions;
vec client_send_cmd(int sd, RSA *pub, const string &cmd, const vec &msg);
void pad0(vec &v, size_t sz);
bool padR(vec &v, size_t sz);
bool enc(RSA *pub, const vec &msg);
void send_result_to_file(const vec &buf, const string &filename);



/// client_key() writes a request for the server's key on a socket descriptor.
/// When it gets it, it writes it to a file.
///
/// @param sd      An open socket
/// @param keyfile The name of the file to which the key should be written
void client_key(int sd, const string &keyfile) {

  // construct key string with just KEY + padding
  vec msg = vec_from_string("KEY");

  //pad vec with 0's?
  pad0(msg, LEN_RKBLOCK);
  
  //send to sd
  if(send_reliably(sd, msg) == false){
    cerr << "send_reliably error in key" << endl;
  }

  //read from sd into a buffer
  vec buffer;
  buffer.reserve(LEN_RSA_PUBKEY);
  buffer = reliable_get_to_eof(sd);

  if(buffer.empty()){
    cerr << "unable to key server pub key" << endl;
  }

  char * data = (char*)buffer.data();
  // write to file
  write_file(keyfile, data, buffer.size()); 
}

/// client_reg() sends the REG command to register a new user
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void client_reg(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &, const string &) {
  vec msg = vec_from_string(user + "\n" + pass + "\n");
  auto res = client_send_cmd(sd, pubkey, REQ_REG, msg);
}

/// client_bye() writes a request for the server to exit.
///
/// @param sd An open socket
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void client_bye(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &, const string &) {
  vec msg = vec_from_string(user + "\n" + pass + "\n");
  auto res = client_send_cmd(sd, pubkey, REQ_BYE, msg);
}

/// client_sav() writes a request for the server to save its contents
///
/// @param sd An open socket
/// @param pubkey  The public key of the server
/// @param user The name of the user doing the request
/// @param pass The password of the user doing the request
void client_sav(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &, const string &) {
  vec msg = vec_from_string(user + "\n" + pass + "\n");
  auto res = client_send_cmd(sd, pubkey, REQ_SAV, msg);
}

/// client_set() sends the SET command to set the content for a user
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param setfile The file whose contents should be sent
void client_set(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &setfile, const string &) {
  vec msg = vec_from_string(user + "\n" + pass + "\n" + setfile);
  auto res = client_send_cmd(sd, pubkey, REQ_SET, msg);
}

/// client_get() requests the content associated with a user, and saves it to a
/// file called <user>.file.dat.
///
/// @param sd      The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param getname The name of the user whose content should be fetched
void client_get(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &getname, const string &) {
  vec msg = vec_from_string(user + "\n" + pass + "\n" + getname);
  auto res = client_send_cmd(sd, pubkey, REQ_GET, msg);
  // Send the result to file, or print an error
  send_result_to_file(res, getname + ".file.dat");
}

/// client_all() sends the ALL command to get a listing of all users, formatted
/// as text with one entry per line.
///
/// @param sd The socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user The name of the user doing the request
/// @param pass The password of the user doing the request
/// @param allfile The file where the result should go
void client_all(int sd, RSA *pubkey, const string &user, const string &pass,
                const string &allfile, const string &) {
  vec msg = vec_from_string(user + "\n" + pass + "\n");
  auto res = client_send_cmd(sd, pubkey, REQ_ALL, msg);
  // Send the result to file, or print an error
  send_result_to_file(res, allfile + ".file.dat");
}

//HELPER FUNCTIONS

/// Pad a vec with \0 characters to get it to size sz
///
/// @param v  The vector to pad
/// @param sz The number of bytes to add
void pad0(vec &v, size_t sz){
  const size_t vec_size = v.size();
  // check if  vec is larger than sz
  if (vec_size > sz){
    //do nothing --- we dont need to pad
  }
  v.resize(vec_size + (sz - vec_size), 0);
}

/// Pad a vec with random characters to get it to size sz
///
/// @param v  The vector to pad
/// @param sz The number of bytes to add
///
/// @returns true if the padding was done, false on any error
bool padR(vec &v, size_t sz){
  const size_t vec_size = v.size();
  // check if  vec is larger than sz
  if (vec_size > sz){
    return false;
  }

  //pad vector using RAND_bytes
  const size_t size_to_pad = sz - v.size();
  vec buffer;
  buffer.reserve(size_to_pad);
  if(RAND_bytes(buffer.data(), size_to_pad) == 0){
    return false;
  }

  //append pad to v
  vec_append(v, buffer);

  return true;
}

/// Check if the provided result vector is a string representation of ERR_CRYPTO
///
/// @param v The vector being compared to RES_ERR_CRYPTO
///
/// @returns true if the vector contents are RES_ERR_CRYPTO, false otherwise
bool check_err_crypto(const vec &v){
  vec err_crypt = vec_from_string(RES_ERR_CRYPTO);
  
  if (v == err_crypt){
    return true;
  }

  return false;
}

/// If a buffer consists of OK.bbbb.d+, where bbbb is a 4-byte binary integer
/// and d+ is a string of characters, write the bytes (d+) to a file
///
/// @param buf      The buffer holding a response
/// @param filename The name of the file to write
void send_result_to_file(const vec &buf, const string &filename){

  //convert req vector to a string
  string vec_string;
  if(!buf.empty()){
    for(char i : buf){
      vec_string += i;
    }
  }

  //parse the string
  //parse OK
  if(strcmp(vec_string.substr(0,2).c_str(), "OK")  != 0){
    cerr << "no OK in sent_result_to_file" << endl;
  }

  //parse binary
  int binary_integer = std::atoi(vec_string.substr(2,4).c_str());
  if(binary_integer <= 0){
    cerr << "binary integer error in sent_result_to_file" << endl;
  }

  //open the file
  vec myFile =  load_entire_file(filename);

  if(!myFile.empty()){
    cerr << "File is empty or could not be opened" << endl;
  }

  //write to file
  if(write_file(filename, vec_string.substr(6, vec_string.length()).c_str(), (vec_string.length() - 6)) == false){
    cerr << "could not write to file in send_result_to_file" << endl;
  }
}

//Method for encrypting with RSA
//
//returns true if encryption succeeded
bool enc(RSA *pub, const vec &msg){
  unsigned char enc[RSA_size(pub)] = {0};
  int len = RSA_public_encrypt(msg.size(), msg.data(), enc, pub, RSA_PKCS1_OAEP_PADDING);
  if(len == -1){
    cerr << "error encrypting with RSA" << endl;
    return false;
  }
  return true;
}

/// Send a message to the server, using the common format for secure messages,
/// then take the response from the server, decrypt it, and return it.
///
/// Many of the messages in our server have a common form (@rblock.@ablock):
///   - @rblock padR(enc(pubkey, "CMD".aeskey.length(@msg)))
///   - @ablock enc(aeskey, @msg)
///
/// @param sd  An open socket
/// @param pub The server's public key, for encrypting the aes key
/// @param cmd The command that is being sent
/// @param msg The contents of the @ablock
///
/// @returns a vector with the (decrypted) result, or an empty vector on error
vec client_send_cmd(int sd, RSA *pub, const string &cmd, const vec &msg){
  //create AES key
  vec key = create_aes_key();
  cerr << "(CLIENT_SENT_CMD): created aes key" << endl;

  //create AES context -- set to true for encryption
  EVP_CIPHER_CTX *ctx = create_aes_context(key, true);
  cerr << "(CLIENT_SENT_CMD): created aes context" << endl;

  //encrypt msg -- do I have to pad msg????!?!?!?!?!?
  vec ablock = aes_crypt_msg(ctx, msg);
  cerr << "(CLIENT_SENT_CMD): aes_crypt_msg finished" << endl;

  //build rblock --- vec, vec reserve, VEC_APPEND
  vec rblock;
  rblock.reserve(LEN_RKBLOCK);
  vec_append(rblock, cmd);
  vec_append(rblock, key);
  vec_append(rblock, key.size());
  cerr << "(CLIENT_SENT_CMD): build rblock" << endl;

  //pad rblock
  bool was_padded = padR(rblock, LEN_RKBLOCK);
  if(was_padded == false){
    //reclaim ctx
    reclaim_aes_context(ctx);

    //error empty vector
    return {};
  }

  //encrypt block
  if(enc(pub, rblock) == false){
    cerr << "Could not encrypt with RSA" << endl;
    return{};
  }

  //write rblock onto socket sd
  if(send_reliably(sd, rblock) == false){
    //reclaim ctx
    reclaim_aes_context(ctx);

    //error
    return {};
  }

  //write ablock onto socket sd
  if(send_reliably(sd, ablock) == false){
    //reclaim ctx
    reclaim_aes_context(ctx);

    //error
    return {};
  }

  //read from sd into a buffer
  vec res;
  res.reserve(LEN_CONTENT);
  res = reliable_get_to_eof(sd);

  if(res.empty()){
    cerr << "unable to get server response" << endl;
    //reclaim ctx
    reclaim_aes_context(ctx);
    //error
    return {};
  }

  //Reset CTX?
  if(reset_aes_context(ctx, key, false) == false){
    //reclaim ctx
    reclaim_aes_context(ctx);
    //error
    return {};
  }

  //decrypt msg w/ aes
  vec dec_ablock = aes_crypt_msg(ctx, msg);
  if(dec_ablock.empty()){
    //reclaim ctx
    reclaim_aes_context(ctx);
    cerr << "could not decrypt ablock from server" << endl;
    return {};
  }

  //reclaim ctx
  reclaim_aes_context(ctx);

  //return server response --- vec
  return dec_ablock;
}