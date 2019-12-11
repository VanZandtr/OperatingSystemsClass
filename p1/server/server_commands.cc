#include <string>
#include <sstream>

#include "../common/crypto.h"
#include "../common/net.h"
#include "../common/protocol.h"
#include "../common/vec.h"

#include "server_commands.h"
#include "server_storage.h"

using namespace std;

//declare helper functions
std::vector<std::string> get_req_args(const vec &req);

/// Respond to an ALL command by generating a list of all the usernames in the
/// Auth table and returning them, one per line.
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_all(int sd, Storage &storage, EVP_CIPHER_CTX *ctx, const vec &req) {
  
  //get username and password from request string
  std::vector<std::string> args = get_req_args(req);
  
  //check we only have 2 args
  if(args.size() != 2){
    //throw error
    cerr << "wrong args in server_cmd_all" << endl;
    return true;
  }

  //get username and pass
  string user_name = args.at(0);
  string pass = args.at(1);

  //get all names from auth table
  pair<bool, vec> result =  storage.get_all_users(user_name, pass);

  vec to_enc = get<1>(result);
  //encrypt result with ctx
  vec enc_string = aes_crypt_msg(ctx, to_enc);
  if (enc_string.empty()){
    cerr << "error: Vector is empty, crypt failed. Exiting server_commands.cc -> server_cmd_all." << endl;
    return true;
  }

  //write onto socket sd
  if(send_reliably(sd, enc_string) == false){
    //error
    return true;
  }

  //server should not stop
  return false;
}

/// Respond to a SET command by putting the provided data into the Auth table
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_set(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {

  //get username and password from request string
  std::vector<std::string> args = get_req_args(req);
  
  //check we only have 3 args
  if(args.size() != 3 ){
    //throw error
    cerr << "wrong args in server_cmd_set" << endl;
    return true;
  }

  //get username,password, and content from vec
  string user_name = args.at(0);
  string pass = args.at(1);
  vec content = vec_from_string(args.at(2));

  //set user content
  vec result_string =  storage.set_user_data(user_name, pass, content);

  //encrypt result with ctx
  vec enc_string = aes_crypt_msg(ctx, result_string);
  if (enc_string.empty()){
    cerr << "error: Vector is empty, crypt failed. Exiting server_commands.cc -> server_cmd_all." << endl;
    return true;
  }

  //write onto socket sd
  if(send_reliably(sd, result_string) == false){
    //error
    return true;
  }

  //server should not stop
  return false;
}

/// Respond to a GET command by getting the data for a user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_get(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  //get username and password from request string
  std::vector<std::string> args = get_req_args(req);
  
  //check we only have 3 args
  if(args.size() != 3 ){
    //throw error
    cerr << "wrong args in server_cmd_set" << endl;
    return true;
  }

  //get username and password
  string user_name = args.at(0);
  string pass = args.at(1);

  //get user content
  pair<bool, vec> result =  storage.get_user_data(user_name, pass, args.at(2));

  //check for error
  if(get<0>(result) == false){
    cerr << "error in get_user_data" << endl;
    return true;
  }

  //get the vec with user data
  vec to_enc = get<1>(result);

  //encrypt result with ctx
  vec enc_string = aes_crypt_msg(ctx, to_enc);
  if (enc_string.empty()){
    cerr << "error: Vector is empty, crypt failed. Exiting server_commands.cc -> server_cmd_all." << endl;
    return true;
  }

  //write onto socket sd
  if(send_reliably(sd, enc_string) == false){
    cerr << "could not send encrypted string" << endl;
    return true;
  }

  //server should not stop
  return false;
}

/// Respond to a REG command by trying to add a new user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @returns false, to indicate that the server shouldn't stop
bool server_cmd_reg(int sd, Storage &storage, EVP_CIPHER_CTX *ctx,
                    const vec &req) {
  //parse args
  std::vector<std::string> args = get_req_args(req);

  //check we only have 2 args (name and password)
  if(args.size() != 2){
    //throw error
    cerr << "wrong args in server_cmd_reg" << endl;
    return true;
  }

  //get usernaem and password
  string user_name = args.at(0);
  string pass = args.at(1);

  //try to reg the user
  bool check_add = storage.add_user(user_name, pass);
  if (check_add == false){
    cerr << "Could not register new user, stop server?\n" << endl;
    //write error on sd
    return true;
  }

  //encrypt
  //encrypt result with ctx
  vec enc_string = aes_crypt_msg(ctx, RES_OK);
  if (enc_string.empty()){
    cerr << "error: Vector is empty, crypt failed. Exiting server_commands.cc -> server_cmd_reg." << endl;
    return true;
  }

  if(send_reliably(sd, enc_string) == false){
    //error
    return true;
  }

  return false;
}

/// In response to a request for a key, do a reliable send of the contents of
/// the pubfile
///
/// @param sd The socket on which to write the pubfile
/// @param pubfile A vector consisting of pubfile contents
void server_cmd_key(int sd, const vec &pubfile) {
  //if we get KEY just send the pubkey
  if(send_reliably(sd, pubfile) == false){
    cerr << "error sending key" << endl;
  }
}

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
                    const vec &req) {
  //parse args
  std::vector<std::string> args = get_req_args(req);

  //check we only have 2 args (name and password)
  if(args.size() != 2){
    //throw error
    cerr << "wrong args in server_cmd_bye" << endl;
    return true;
  }

  //get username and pass
  string user_name = args.at(0);
  string pass = args.at(1);

  bool is_auth = storage.auth(user_name, pass);
  if(is_auth == false){
    cerr << "could not auth user, server will continue" << endl;
    return false;
  }

  //encrypt result with ctx
  vec enc_string = aes_crypt_msg(ctx, RES_OK);
  if (enc_string.empty()){
    cerr << "error: Vector is empty, crypt failed. Exiting server_commands.cc -> server_cmd_reg." << endl;
    return true;
  }

  //write to sd ---> OK
  if(send_reliably(sd, enc_string) == false){
    //error
    return true;
  }

  return true;

}

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
                    const vec &req) {
  //parse args
  std::vector<std::string> args = get_req_args(req);

  //check we only have 2 args (name and password)
  if(args.size() != 2){
    //throw error
    cerr << "wrong args in server_cmd_sav" << endl;
    return true;
  }

  string user_name = args.at(0);
  string pass = args.at(1);

  bool is_auth = storage.auth(user_name, pass);
  if(is_auth == false){
    cerr << "could not auth user, server will exit and not save" << endl;
    return true;
  }

  //ENCRYPT?
  //WHAT TO WRITE ON SD?
  
  //save
  storage.persist();
  cerr << "saving content and continuing\n" <<endl;
  return false;  
}

//HELPER FUNCTION

std::vector<std::string> get_req_args(const vec &req){
  //convert req vector to a string
  std::string vec_string;
  if(!req.empty()){
    for(char i : req){
      vec_string += i;
    }
  }

  //split string by \n
  std::vector<std::string> array;
  std::string token;
  std::istringstream ss(vec_string);
  while(std::getline(ss, token, '\n')){
    //push args to a vector
    array.push_back(token);
  }
  return array;
}