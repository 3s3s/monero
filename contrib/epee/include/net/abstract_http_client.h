#pragma once

#include <boost/optional/optional.hpp>
#include "http_base.h"
#include "http_auth.h"
#include "net_parse_helpers.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.http"

namespace epee
{
  namespace net_utils
  {
    namespace http
    {
      /**
       * Abstract HTTP client interface.
       */
      class abstract_http_client
      {
      public:
        bool set_server(const std::string& address, boost::optional<login> user)
        {
          http::url_content parsed{};
          const bool r = parse_url(address, parsed);
          CHECK_AND_ASSERT_MES(r, false, "failed to parse url: " << address);
          set_server(std::move(parsed.host), std::to_string(parsed.port), std::move(user));
          return true;
        }
        void set_server(std::string host, std::string port, boost::optional<login> user);
        void set_auto_connect(bool auto_connect);
        template<typename F>
        void set_connector(F connector);
        bool connect(std::chrono::milliseconds timeout);
        bool disconnect();
        bool is_connected(bool *ssl = NULL);
        virtual bool invoke(const boost::string_ref uri, const boost::string_ref method, const std::string& body, std::chrono::milliseconds timeout, const http_response_info** ppresponse_info = NULL, const fields_list& additional_params = fields_list()) = 0;
        virtual bool invoke_get(const boost::string_ref uri, std::chrono::milliseconds timeout, const std::string& body = std::string(), const http_response_info** ppresponse_info = NULL, const fields_list& additional_params = fields_list()) = 0;
        virtual bool invoke_post(const boost::string_ref uri, const std::string& body, std::chrono::milliseconds timeout, const http_response_info** ppresponse_info = NULL, const fields_list& additional_params = fields_list()) = 0;
        uint64_t get_bytes_sent() const;
        uint64_t get_bytes_received() const;
      };
    }
  }
}
