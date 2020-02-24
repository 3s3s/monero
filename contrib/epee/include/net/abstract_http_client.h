#pragma once

#include <boost/optional/optional.hpp>
#include "http_base.h"
#include "http_auth.h"
#include "net/net_ssl.h"
#include "net_parse_helpers.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.http"

namespace epee
{
  namespace net_utils
  {
    inline const char* get_hex_vals()
    {
      static constexpr const char hexVals[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
      return hexVals;
    }

    inline const char* get_unsave_chars()
    {
      //static constexpr char unsave_chars[] = "\"<>%\\^[]`+$,@:;/!#?=&";
      static constexpr const char unsave_chars[] = "\"<>%\\^[]`+$,@:;!#&";
      return unsave_chars;
    }

    bool is_unsafe(unsigned char compare_char);
    std::string dec_to_hex(char num, int radix);
    int get_index(const char *s, char c);
    std::string hex_to_dec_2bytes(const char *s);
    std::string convert(char val);
    std::string conver_to_url_format(const std::string& uri);
    std::string convert_from_url_format(const std::string& uri);
    std::string convert_to_url_format_force_all(const std::string& uri);

    namespace http
    {
      /**
       * Abstract HTTP client interface.
       */
      class abstract_http_client
      {
      public:
        abstract_http_client() {}
        virtual ~abstract_http_client() {}
        virtual bool set_server(const std::string& address, boost::optional<login> user, ssl_options_t ssl_options = ssl_support_t::e_ssl_support_autodetect)
        {
          http::url_content parsed{};
          const bool r = parse_url(address, parsed);
          CHECK_AND_ASSERT_MES(r, false, "failed to parse url: " << address);
          set_server(std::move(parsed.host), std::to_string(parsed.port), std::move(user), std::move(ssl_options));
          return true;
        }
        virtual void set_server(std::string host, std::string port, boost::optional<login> user, ssl_options_t ssl_options = ssl_support_t::e_ssl_support_autodetect) = 0;
        virtual void set_auto_connect(bool auto_connect) = 0;
        virtual bool connect(std::chrono::milliseconds timeout) = 0;
        virtual bool disconnect() = 0;
        virtual bool is_connected(bool *ssl = NULL) = 0;
        virtual bool invoke(const boost::string_ref uri, const boost::string_ref method, const std::string& body, std::chrono::milliseconds timeout, const http_response_info** ppresponse_info = NULL, const fields_list& additional_params = fields_list()) = 0;
        virtual bool invoke_get(const boost::string_ref uri, std::chrono::milliseconds timeout, const std::string& body = std::string(), const http_response_info** ppresponse_info = NULL, const fields_list& additional_params = fields_list()) = 0;
        virtual bool invoke_post(const boost::string_ref uri, const std::string& body, std::chrono::milliseconds timeout, const http_response_info** ppresponse_info = NULL, const fields_list& additional_params = fields_list()) = 0;
        virtual uint64_t get_bytes_sent() const = 0;
        virtual uint64_t get_bytes_received() const = 0;
      };
    }
  }
}
