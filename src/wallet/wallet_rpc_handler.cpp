// Copyright (c) 2017-2020, The Monero Project
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

#include "wallet_rpc_handler.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include <boost/uuid/nil_generator.hpp>
#include <boost/utility/string_ref.hpp>
// likely included by daemon_handler.h's includes,
// but including here for clarity
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/blobdatatype.h"
#include "ringct/rctSigs.h"
#include "version.h"

#include <rapidjson/writer.h>
//#include "rapidjson/document.h" // TODO (woodser): how does daemon_handler.cpp use these?
//#include "rapidjson/writer.h"
//#include "rapidjson/stringbuffer.h"

#include "rpc/message.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "rpc/message_data_structs.h"
#include "cryptonote_basic/cryptonote_basic.h"

namespace cryptonote
{

namespace rpc
{
  namespace
  {
    using handler_function = epee::byte_slice(WalletRpcHandler& handler, const rapidjson::Value& id, const rapidjson::Value& msg);
    struct handler_map
    {
      const char* method_name;
      handler_function* call;
    };

    bool operator<(const handler_map& lhs, const handler_map& rhs) noexcept
    {
      return std::strcmp(lhs.method_name, rhs.method_name) < 0;
    }

    bool operator<(const handler_map& lhs, const std::string& rhs) noexcept
    {
      return std::strcmp(lhs.method_name, rhs.c_str()) < 0;
    }

    template<typename Message>
    epee::byte_slice handle_message(WalletRpcHandler& handler, const rapidjson::Value& id, const rapidjson::Value& parameters)
    {
      typename Message::Request request{};
      request.fromJson(parameters);

      typename Message::Response response{};
      handler.handle(request, response);
      return FullMessage::getResponse(response, id);
    }
  } // anonymous

  WalletRpcHandler::WalletRpcHandler()
  {
    //const auto last_sorted = std::is_sorted_until(std::begin(handlers), std::end(handlers));
    //if (last_sorted != std::end(handlers))
    //  throw std::logic_error{std::string{"ZMQ JSON-RPC handlers map is not properly sorted, see "} + last_sorted->method_name};
  }

  epee::byte_slice WalletRpcHandler::handle(std::string&& request)
  {
    MDEBUG("Handling RPC request: " << request);
    std::cout << "HANDLING RPC REQUEST: " << request << std::endl;
    throw std::runtime_error("Not implemented");

//    try
//    {
//      FullMessage req_full(std::move(request), true);
//
//      const std::string request_type = req_full.getRequestType();
//      const auto matched_handler = std::lower_bound(std::begin(handlers), std::end(handlers), request_type);
//      if (matched_handler == std::end(handlers) || matched_handler->method_name != request_type)
//        return BAD_REQUEST(request_type, req_full.getID());
//
//      epee::byte_slice response = matched_handler->call(*this, req_full.getID(), req_full.getMessage());
//
//      const boost::string_ref response_view{reinterpret_cast<const char*>(response.data()), response.size()};
//      MDEBUG("Returning RPC response: " << response_view);
//
//      return response;
//    }
//    catch (const std::exception& e)
//    {
//      return BAD_JSON(e.what());
//    }
  }

}  // namespace rpc

}  // namespace cryptonote
