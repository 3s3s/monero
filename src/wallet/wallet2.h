// Copyright (c) 2014-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include "wallet2_base.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.wallet2"

using namespace std;

namespace tools
{
  class wallet2 : public wallet2_base {
    //friend class wallet2;

  public:

    // overload move assignment operator
//    wallet2& operator=(const wallet2&& other)
//    {
////      if (this != &other) {
////        (wallet2&)(*this) = other; // TODO
////      }
//      //wallet2::operator=(other);
//      return *this;
//    }

//    // overload assignment operator to return derived class
//    wallet2& operator=(const unique_ptr<wallet2>& other)
//    {
////      if (this != &other) {
////        (wallet2&)(*this) = other; // TODO
////      }
//      //wallet2::operator=(other);
//      return *this;
//    }

//    Eployee& operator=(const Eployee& empl) {
//         74.          if ( this != &empl ) {
//         75.              (Person&)(*this) = empl;
//         76.              delete [] position;
//         77.              position = strcpy(new
//         78.                  char[strlen(empl.position)+1],
//         79.                  empl.position);
//         80.              cout << "Assignment Eployee: "
//         81.                   << position << endl;
//         82.          }
//         83.          return *this;
//         84.      }

//    // move assignment operator
//    wallet2& operator=(wallet2_base&& other) {
//      return *this; // TODO
//    }
//
//    // move constructor
//    wallet2(wallet2_base&& other) : wallet2_base(cryptonote::MAINNET, 1, false) {  // TODO: invoke super with default params
//      // TODO
//    }

//    // move assignment operator
//    wallet2& operator=(const unique_ptr<wallet2>&& other) {
//      return *this; // TODO
//    }

//    // move constructor
//    wallet2(const unique_ptr<wallet2_base>&& other) : wallet2_base(cryptonote::MAINNET, 1, false) {  // TODO: invoke super with default params
//     // TODO
//    }

//    // copy assignment operator
//    wallet2& operator=(wallet2& other) {
//      return *this; // TODO
//    }
//
//    // copy constructor
//    wallet2(wallet2& other) : wallet2_base(other) {  // TODO: invoke super with default params
//      // TODO
//    }

//    // copy assignment operator
//    wallet2& operator=(const unique_ptr<wallet2>& other) {
//      return *this; // TODO
//    }
//
//    // copy assignment operator
//    wallet2& operator=(const unique_ptr<wallet2_base>& other) {
//      return *this; // TODO
//    }

    //using wallet2_base::operator=;

//    wallet2(const unique_ptr<wallet2_base>& other) {
//      // TODO
//    }

//    wallet2(const unique_ptr<wallet2>& other) {
//      // TODO
//    }
//
////    wallet2(const unique_ptr<wallet2_base>&& other) {
////      // TODO
////    }
//
//    wallet2(const unique_ptr<wallet2>&& other) {
//      // TODO
//    }

//    // move assignment operator
//    wallet2& operator=(const wallet2&& other) {
//      return *this; // TODO
//    }
//
//    // move constructor
//    wallet2(const wallet2&& other) : wallet2_base(cryptonote::MAINNET, 1, false) {  // TODO: invoke super with default params
//      // todo
//    }

//    wallet2& operator=(wallet2& other) {
//      return *this; // TODO
//    }

    //using wallet2_base::operator=;

    wallet2(cryptonote::network_type nettype = cryptonote::MAINNET, uint64_t kdf_rounds = 1, bool unattended = false);
    ~wallet2();

    //! Uses stdin and stdout. Returns a wallet2 and password for `wallet_file` if no errors.
    static std::pair<std::unique_ptr<wallet2>, password_container>
      make_from_file(const boost::program_options::variables_map& vm, bool unattended, const std::string& wallet_file, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter);

    //! Uses stdin and stdout. Returns a wallet2 and password for wallet with no file if no errors.
    static std::pair<std::unique_ptr<wallet2>, password_container> make_new(const boost::program_options::variables_map& vm, bool unattended, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter);

    //! Uses stdin and stdout. Returns a wallet2_base if no errors.
    static std::pair<std::unique_ptr<wallet2>, password_container> make_from_json(const boost::program_options::variables_map& vm, bool unattended, const std::string& json_file, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter);
  };
}
