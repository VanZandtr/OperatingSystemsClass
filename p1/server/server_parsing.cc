#include <cstring>
#include <iostream>
#include <openssl/rsa.h>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_commands.h"
#include "server_parsing.h"
#include "server_storage.h"

using namespace std;
//declare helper functions
bool rsa_decrypt(RSA *pri, vec &msg);

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
bool serve_client(int sd, RSA *pri, const vec &pub, Storage &storage) {
  cerr << "serving client" << endl;
  
  //read from sd into a buffer
  vec res;
  res.reserve(LEN_RKBLOCK);
  res = reliable_get_to_eof(sd);
  
  //check len of res
  if(res.empty()){
    cerr << "Recieved Msg is empty" << endl;
    return false;
  }
  
  //check if KEY --- send pub
  if(res.at(0) == 'K' && res.at(1) == 'E' && res.at(2) == 'Y'){
    if(send_reliably(sd, pub) == false){
      cerr << "could not send rsa key, exiting" << endl;
      return true;
    }
    return false;
  }
  
  //convert req vector to a string
  std::string vec_string;
  if(!res.empty()){
    for(char i : res){
      vec_string += i;
    }
  }

  //get cmd and aes key
  string cmd = vec_string.substr(0, 6);
  string aes_key_string = vec_string.substr(6, AES_KEYSIZE);
  
  //aes key - start after cmd -----> end of AES_KEYSIZE = + 6 -1 = 5
  vec aes_key = vec_from_string(aes_key_string);
  
  //get the rest of sd
  vec enc_ablock;
  enc_ablock.reserve(AES_BLOCKSIZE);
  enc_ablock = reliable_get_to_eof(sd);
  
  //check ablock size
  if(enc_ablock.size() != AES_BLOCKSIZE){
    cerr << "aesblock size" + enc_ablock.size() << endl;
    cerr << AES_BLOCKSIZE << endl;
    cerr << "aesblock not the right length" << endl;
    return true;
  }
  
  //decrypt ablock
  EVP_CIPHER_CTX *ctx = create_aes_context(aes_key, false);
  
  //decrypt msg
  vec ablock = aes_crypt_msg(ctx, enc_ablock);
  if(ablock.empty()){
    reclaim_aes_context(ctx);
    cerr << "ablock is empty" << endl;
    return false;
  }
  
  //reset ctx context for server_cmd encryption
  if(reset_aes_context(ctx, aes_key, true)){
    reclaim_aes_context(ctx);
    cerr << "could not reset ctx to encrypt for server_commands" << endl;
    return true;
  }
  
  // Iterate through possible commands, pick the right one, run it
  std::vector<std::string> s = {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
  decltype(server_cmd_reg) *cmds[] = {server_cmd_reg, server_cmd_bye, server_cmd_sav, server_cmd_set, server_cmd_get, server_cmd_all};
  for (size_t i = 0; i < s.size(); ++i) {
    if (cmd == s[i]) {
      
      //run the server_commands.cc command
      return cmds[i](sd, storage, ctx, ablock);
    }
  }
  return true;
}

//Method used to decrypt RSA
bool rsa_decrypt(RSA *pri, vec &msg){
   unsigned char dec[RSA_size(pri)] = {0};
   int len = RSA_private_decrypt(msg.size(), msg.data(), dec, pri, RSA_PKCS1_OAEP_PADDING);
   if(len == -1){
     cerr << "Error decrypting RSA msg\n" << endl;
     return false; 
   }
   return true;
 }