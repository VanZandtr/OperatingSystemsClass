#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <string>
#include <sys/stat.h>

#include "contextmanager.h"
#include "crypto.h"
#include "vec.h"

using namespace std;

/// Load an RSA public key from the given filename
///
/// @param filename The name of the file that has the public key in it
///
/// @returns An RSA context for encrypting with the provided public key, or
///          nullptr on error
RSA *load_pub(const char *filename) {
  FILE *pub = fopen(filename, "r");
  if (pub == nullptr) {
    cerr << "Error opening public key file\n";
    return nullptr;
  }
  RSA *rsa = PEM_read_RSAPublicKey(pub, nullptr, nullptr, nullptr);
  if (rsa == nullptr) {
    fclose(pub);
    cerr << "Error reading public key file\n";
    return nullptr;
  }
  return rsa;
}

/// Load an RSA private key from the given filename
///
/// @param filename The name of the file that has the private key in it
///
/// @returns An RSA context for encrypting with the provided private key, or
///          nullptr on error
RSA *load_pri(const char *filename) {
  FILE *pri = fopen(filename, "r");
  if (pri == nullptr) {
    cerr << "Error opening private key file\n";
    return nullptr;
  }
  RSA *rsa = PEM_read_RSAPrivateKey(pri, nullptr, nullptr, nullptr);
  if (rsa == nullptr) {
    fclose(pri);
    cerr << "Error reading public key file\n";
    return nullptr;
  }
  return rsa;
}

/// Produce an RSA key and save its public and private parts to files
///
/// @param pub The name of the public key file to generate
/// @param pri The name of the private key file to generate
///
/// @returns true on success, false on any error
bool generate_rsa_key_files(const string &pub, const string &pri) {
  cout << "Generating RSA keys as (" << pub << ", " << pri << ")\n";
  // When we create a new RSA keypair, we need to know the #bits (see constant
  // above) and the desired exponent to use in the public key.  The exponent
  // needs to be a bignum.  We'll use the RSA_F4 default value:
  BIGNUM *bn = BN_new();
  if (bn == nullptr) {
    cerr << "Error in BN_new()\n";
    return false;
  }
  ContextManager bnfree([&]() { BN_free(bn); }); // ensure bn gets freed

  if (BN_set_word(bn, RSA_F4) != 1) {
    cerr << "Error in BN_set_word()\n";
    return false;
  }

  // Now we can create the key pair
  RSA *rsa = RSA_new();
  if (rsa == nullptr) {
    cerr << "Error in RSA_new()\n";
    return false;
  }
  ContextManager rsafree([&]() { RSA_free(rsa); }); // ensure rsa gets freed

  if (RSA_generate_key_ex(rsa, RSA_KEYSIZE, bn, nullptr) != 1) {
    cerr << "Error in RSA_genreate_key_ex()\n";
    return false;
  }

  // Create/truncate the files
  FILE *pubfile = fopen(pub.c_str(), "w");
  if (pubfile == nullptr) {
    cerr << "Error opening public key file for output\n";
    return false;
  }
  ContextManager pubclose([&]() { fclose(pubfile); }); // ensure pub gets closed

  FILE *prifile = fopen(pri.c_str(), "w");
  if (prifile == nullptr) {
    cerr << "Error opening private key file for output\n";
    return false;
  }
  ContextManager priclose([&]() { fclose(prifile); }); // ensure pub gets closed

  // Perform the writes.  Defer cleanup on error, because the cleanup is the
  // same
  if (PEM_write_RSAPublicKey(pubfile, rsa) != 1) {
    cerr << "Error writing public key\n";
    return false;
  } else if (PEM_write_RSAPrivateKey(prifile, rsa, nullptr, nullptr, 0, nullptr,
                                     nullptr) != 1) {
    cerr << "Error writing private key\n";
    return false;
  }

  return true;
}

/// Run the AES symmetric encryption/decryption algorithm on a buffer of bytes.
/// Note that this will do either encryption or decryption, depending on how the
/// provided CTX has been configured.  After calling, the CTX cannot be used
/// until it is reset.
///
/// @param ctx The pre-configured AES context to use for this operatoin
/// @param start A buffer of bytes to encrypt/decrypt
/// @param count assumed buffer size
///
/// @returns A vector with the encrypted or decrypted result, or an empty vector
vec aes_crypt_msg(EVP_CIPHER_CTX *ctx, const unsigned char *start, int count) {
  cerr << "(AES_CRYPT_MSG): in aes_crypt_msg" << endl;
  //make vec
  vec out_vec;
  out_vec.reserve(AES_BLOCKSIZE);

  // figure out the block size that AES is going to use
  int cipher_block_size = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx));
  cerr << "(AES_CRYPT_MSG): cipher_block_size" << endl;
  // Set up a buffer where AES puts crypted bits.  Since the last block is
  // special, we need this outside the loop.
  unsigned char out_buf[AES_BUFSIZE + cipher_block_size];
  int out_len;
  //get current pointer
  const unsigned char *current = start;
  // Read blocks from the file and crypt them:
  while (true) {
    // crypt in_buf into out_buf
    if (!EVP_CipherUpdate(ctx, out_buf, &out_len, current, AES_BUFSIZE)) {
      cerr << "error" << endl;
      fprintf(stderr, "Error in EVP_CipherUpdate: %s\n",
              ERR_error_string(ERR_get_error(), nullptr));
      return {};
    }
    //increment point by bufsize
    current += AES_BUFSIZE;
    //convert to string
    string app_string = string((const char*)out_buf);
    //write outbut to out_vec
    vec_append(out_vec, app_string);
    // stop on EOF
    if (out_len < AES_BUFSIZE) {
      cerr << "(AES_CRYPT_MSG): broke while loop";
      break;
    }
  }
  // The final block needs special attention!
  if (!EVP_CipherFinal_ex(ctx, out_buf, &out_len)) {
    fprintf(stderr, "Error in EVP_CipherFinal_ex: %s\n",
            ERR_error_string(ERR_get_error(), nullptr));
    return {};
  }
  //convert to string
  string ret_string = string((const char*)out_buf);
  //write outbut to out_vec
  vec_append(out_vec, ret_string);
  return out_vec;
}

/// Run the AES symmetric encryption/decryption algorithm on a vector of bytes.
/// Note that this will do either encryption or decryption, depending on how the
/// provided CTX has been configured.  After calling, the CTX cannot be used
/// until it is reset.
///
/// @param ctx The pre-configured AES context to use for this operatoin
/// @param msg A vector of bytes to encrypt/decrypt
///
/// @returns A vector with the encrypted or decrypted result, or an empty vector
vec aes_crypt_msg(EVP_CIPHER_CTX *ctx, const vec &msg) {
  return aes_crypt_msg(ctx, msg.data(), msg.size());
}

/// Run the AES symmetric encryption/decryption algorithm on a string. Note that
/// this will do either encryption or decryption, depending on how the provided
/// CTX has been configured.  After calling, the CTX cannot be used until it is
/// reset.
///
/// @param ctx The pre-configured AES context to use for this operatoin
/// @param msg A string to encrypt/decrypt
///
/// @returns A vector with the encrypted or decrypted result, or an empty vector
vec aes_crypt_msg(EVP_CIPHER_CTX *ctx, const string &msg) {
  return aes_crypt_msg(ctx, (unsigned char *)msg.c_str(), msg.length());
}

/// Create an AES key.  A key is two parts, the key itself, and the
/// initialization vector.  Each is just random bits.  Our key will just be a
/// stream of random bits, long enough to be split into the actual key and the
/// iv.
///
/// @returns a vector holding the key and iv bits
vec create_aes_key() {
  vec key(AES_KEYSIZE + AES_BLOCKSIZE);
  if (!RAND_bytes(key.data(), AES_KEYSIZE) ||
      !RAND_bytes(key.data() + AES_KEYSIZE, AES_BLOCKSIZE)) {
    cerr << "Error in RAND_bytes()\n";
    return {};
  }
  return key;
}

/// Create an aes context for doing a single encryption or decryption.  The
/// context must be reset after each full encrypt/decrypt.
///
/// @param key     A vector holding the bits of the key and iv
/// @param encrypt True to encrypt, false to decrypt
///
/// @returns An AES context for doing encryption.  Note that the context can be
///          reset in order to re-use this object for another encryption.
EVP_CIPHER_CTX *create_aes_context(const vec &key, bool encrypt) {
  // create and initialize a context for the AES operations we are going to do
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == nullptr) {
    cerr << "Error: OpenSSL couldn't create context: "
         << ERR_error_string(ERR_get_error(), nullptr) << endl;
    return nullptr;
  }
  ContextManager c([&]() { EVP_CIPHER_CTX_cleanup(ctx); }); // reclaim on exit

  // Make sure the key and iv lengths we have up above are valid
  if (!EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), nullptr, nullptr, nullptr,
                         encrypt)) {
    cerr << "Error: OpenSSL couldn't initialize context: "
         << ERR_error_string(ERR_get_error(), nullptr) << endl;
    return nullptr;
  }
  if ((EVP_CIPHER_CTX_key_length(ctx) != AES_KEYSIZE) ||
      (EVP_CIPHER_CTX_iv_length(ctx) != AES_BLOCKSIZE)) {
    cerr << "Error: OpenSSL couldn't initialize context: "
         << ERR_error_string(ERR_get_error(), nullptr) << endl;
    return nullptr;
  }

  // Set the key and iv on the AES context, and set the mode to encrypt or
  // decrypt
  if (!EVP_CipherInit_ex(ctx, nullptr, nullptr, key.data(),
                         key.data() + AES_KEYSIZE, encrypt)) {
    cerr << "Error: OpenSSL couldn't re-init context: "
         << ERR_error_string(ERR_get_error(), nullptr) << endl;
    return nullptr;
  }
  c.cancel(); // don't reclaim ctx on exit, because we're good
  return ctx;
}

/// Reset an existing AES context, so that we can use it for another
/// encryption/decryption
///
/// @param ctx     The AES context to reset
/// @param key     A vector holding the bits of the key and iv.  Should be
///                generated by create_aes_key().
/// @param encrypt True to create an encryption context, false to create a
///                decryption context
///
/// @returns false on error, true if the context is reset and ready to use again
bool reset_aes_context(EVP_CIPHER_CTX *ctx, vec &key, bool encrypt) {
  if (!EVP_CipherInit_ex(ctx, nullptr, nullptr, key.data(),
                         key.data() + AES_KEYSIZE, encrypt)) {
    cerr << "Error: OpenSSL couldn't re-init context: "
         << ERR_error_string(ERR_get_error(), nullptr) << endl;
    EVP_CIPHER_CTX_cleanup(ctx);
    return false;
  }
  return true;
}

/// When an AES context is done being used, call this to reclaim its memory
///
/// @param ctx The context to reclaim
void reclaim_aes_context(EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_cleanup(ctx); }

/// If the given basename resolves to basename.pri and basename.pub, then load
/// basename.pri and return it.  If one or the other doesn't exist, then there's
/// an error.  If both don't exist, create them and then load basename.pri.
///
/// @param basename The basename of the .pri and .pub files for RSA
///
/// @returns The RSA context from loading the private file, or nullptr on error
RSA *init_RSA(const string &basename) {
  string pubfile = basename + ".pub", prifile = basename + ".pri";

  struct stat stat_buf;
  bool pub_exists = (stat(pubfile.c_str(), &stat_buf) == 0);
  bool pri_exists = (stat(prifile.c_str(), &stat_buf) == 0);

  if (!pub_exists && !pri_exists) {
    generate_rsa_key_files(pubfile, prifile);
  } else if (pub_exists && !pri_exists) {
    cerr << "Error: cannot find " << basename << ".pri\n";
    return nullptr;
  } else if (!pub_exists && pri_exists) {
    cerr << "Error: cannot find " << basename << ".pub\n";
    return nullptr;
  }
  return load_pri(prifile.c_str());
}