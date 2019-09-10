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

#include "wallet2.h"

using namespace std;
using namespace crypto;
using namespace cryptonote;

namespace tools {

wallet2::wallet2(network_type nettype, uint64_t kdf_rounds, bool unattended)
{
}

wallet2::~wallet2()
{
}

std::pair<std::unique_ptr<wallet2>, password_container> wallet2::make_from_file(
  const boost::program_options::variables_map& vm, bool unattended, const std::string& wallet_file, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  //return static_pointer_cast<wallet2>(wallet2_base::make_from_file(vm, unattended, wallet_file, password_prompter));
}

std::pair<std::unique_ptr<wallet2>, password_container> wallet2::make_new(const boost::program_options::variables_map& vm, bool unattended, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter)
{
  // TODO
}

//// move assignment operator
//wallet2& wallet2::operator=(const wallet2_base&& other) {
//  return *this; // TODO
//}

//// move constructor
//wallet2::wallet2(const wallet2_base&& other) : wallet2_base(cryptonote::MAINNET, 1, false) {  // TODO: invoke super with default params
//  // TODO
//}

std::pair<std::unique_ptr<wallet2>, tools::password_container> wallet2::make_from_json(const boost::program_options::variables_map& vm, bool unattended, const std::string& json_file, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
{
  // TODO
}

}
