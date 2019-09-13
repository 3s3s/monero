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

#include <numeric>
#include <tuple>
#include <boost/format.hpp>
#include <boost/optional/optional.hpp>
#include <boost/utility/value_init.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/preprocessor/stringize.hpp>
#include "include_base_utils.h"
using namespace epee;

#include "cryptonote_config.h"
#include "wallet2.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "misc_language.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "multisig/multisig.h"
#include "common/boost_serialization_helper.h"
#include "common/command_line.h"
#include "common/threadpool.h"
#include "profile_tools.h"
#include "crypto/crypto.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "cryptonote_basic/blobdatatype.h"
#include "mnemonics/electrum-words.h"
#include "common/i18n.h"
#include "common/util.h"
#include "common/apply_permutation.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "common/json_util.h"
#include "memwipe.h"
#include "common/base58.h"
#include "common/combinator.h"
#include "common/dns_utils.h"
#include "common/notify.h"
#include "common/perf_timer.h"
#include "ringct/rctSigs.h"
#include "ringdb.h"
#include "device/device_cold.hpp"
#include "device_trezor/device_trezor.hpp"
#include "net/socks_connect.h"

extern "C"
{
#include "crypto/keccak.h"
#include "crypto/crypto-ops.h"
}

using namespace std;
using namespace crypto;
using namespace cryptonote;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.wallet2"

namespace
{
  std::string get_default_ringdb_path()
  {
    boost::filesystem::path dir = tools::get_default_data_dir();
    // remove .bitmonero, replace with .shared-ringdb
    dir = dir.remove_filename();
    dir /= ".shared-ringdb";
    return dir.string();
  }

  // Create on-demand to prevent static initialization order fiasco issues.
  struct options {
    const command_line::arg_descriptor<std::string> daemon_address = {"daemon-address", tools::wallet2::tr("Use daemon instance at <host>:<port>"), ""};
    const command_line::arg_descriptor<std::string> daemon_host = {"daemon-host", tools::wallet2::tr("Use daemon instance at host <arg> instead of localhost"), ""};
    const command_line::arg_descriptor<std::string> proxy = {"proxy", tools::wallet2::tr("[<ip>:]<port> socks proxy to use for daemon connections"), {}, true};
    const command_line::arg_descriptor<bool> trusted_daemon = {"trusted-daemon", tools::wallet2::tr("Enable commands which rely on a trusted daemon"), false};
    const command_line::arg_descriptor<bool> untrusted_daemon = {"untrusted-daemon", tools::wallet2::tr("Disable commands which rely on a trusted daemon"), false};
    const command_line::arg_descriptor<std::string> password = {"password", tools::wallet2::tr("Wallet password (escape/quote as needed)"), "", true};
    const command_line::arg_descriptor<std::string> password_file = {"password-file", tools::wallet2::tr("Wallet password file"), "", true};
    const command_line::arg_descriptor<int> daemon_port = {"daemon-port", tools::wallet2::tr("Use daemon instance at port <arg> instead of 18081"), 0};
    const command_line::arg_descriptor<std::string> daemon_login = {"daemon-login", tools::wallet2::tr("Specify username[:password] for daemon RPC client"), "", true};
    const command_line::arg_descriptor<std::string> daemon_ssl = {"daemon-ssl", tools::wallet2::tr("Enable SSL on daemon RPC connections: enabled|disabled|autodetect"), "autodetect"};
    const command_line::arg_descriptor<std::string> daemon_ssl_private_key = {"daemon-ssl-private-key", tools::wallet2::tr("Path to a PEM format private key"), ""};
    const command_line::arg_descriptor<std::string> daemon_ssl_certificate = {"daemon-ssl-certificate", tools::wallet2::tr("Path to a PEM format certificate"), ""};
    const command_line::arg_descriptor<std::string> daemon_ssl_ca_certificates = {"daemon-ssl-ca-certificates", tools::wallet2::tr("Path to file containing concatenated PEM format certificate(s) to replace system CA(s).")};
    const command_line::arg_descriptor<std::vector<std::string>> daemon_ssl_allowed_fingerprints = {"daemon-ssl-allowed-fingerprints", tools::wallet2::tr("List of valid fingerprints of allowed RPC servers")};
    const command_line::arg_descriptor<bool> daemon_ssl_allow_any_cert = {"daemon-ssl-allow-any-cert", tools::wallet2::tr("Allow any SSL certificate from the daemon"), false};
    const command_line::arg_descriptor<bool> daemon_ssl_allow_chained = {"daemon-ssl-allow-chained", tools::wallet2::tr("Allow user (via --daemon-ssl-ca-certificates) chain certificates"), false};
    const command_line::arg_descriptor<bool> testnet = {"testnet", tools::wallet2::tr("For testnet. Daemon must also be launched with --testnet flag"), false};
    const command_line::arg_descriptor<bool> stagenet = {"stagenet", tools::wallet2::tr("For stagenet. Daemon must also be launched with --stagenet flag"), false};
    const command_line::arg_descriptor<std::string, false, true, 2> shared_ringdb_dir = {
      "shared-ringdb-dir", tools::wallet2::tr("Set shared ring database path"),
      get_default_ringdb_path(),
      {{ &testnet, &stagenet }},
      [](std::array<bool, 2> testnet_stagenet, bool defaulted, std::string val)->std::string {
        if (testnet_stagenet[0])
          return (boost::filesystem::path(val) / "testnet").string();
        else if (testnet_stagenet[1])
          return (boost::filesystem::path(val) / "stagenet").string();
        return val;
      }
    };
    const command_line::arg_descriptor<uint64_t> kdf_rounds = {"kdf-rounds", tools::wallet2::tr("Number of rounds for the key derivation function"), 1};
    const command_line::arg_descriptor<std::string> hw_device = {"hw-device", tools::wallet2::tr("HW device to use"), ""};
    const command_line::arg_descriptor<std::string> hw_device_derivation_path = {"hw-device-deriv-path", tools::wallet2::tr("HW device wallet derivation path (e.g., SLIP-10)"), ""};
    const command_line::arg_descriptor<std::string> tx_notify = { "tx-notify" , "Run a program for each new incoming transaction, '%s' will be replaced by the transaction hash" , "" };
    const command_line::arg_descriptor<bool> no_dns = {"no-dns", tools::wallet2::tr("Do not use DNS"), false};
    const command_line::arg_descriptor<bool> offline = {"offline", tools::wallet2::tr("Do not connect to a daemon, nor use DNS"), false};
    const command_line::arg_descriptor<std::string> extra_entropy = {"extra-entropy", tools::wallet2::tr("File containing extra entropy to initialize the PRNG (any data, aim for 256 bits of entropy to be useful, wihch typically means more than 256 bits of data)")};
  };

  std::unique_ptr<tools::wallet2> make_basic(const boost::program_options::variables_map& vm, bool unattended, const options& opts, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
  {
    namespace ip = boost::asio::ip;

    const bool testnet = command_line::get_arg(vm, opts.testnet);
    const bool stagenet = command_line::get_arg(vm, opts.stagenet);
    const network_type nettype = testnet ? TESTNET : stagenet ? STAGENET : MAINNET;
    const uint64_t kdf_rounds = command_line::get_arg(vm, opts.kdf_rounds);
    THROW_WALLET_EXCEPTION_IF(kdf_rounds == 0, tools::error::wallet_internal_error, "KDF rounds must not be 0");

    const bool use_proxy = command_line::has_arg(vm, opts.proxy);
    auto daemon_address = command_line::get_arg(vm, opts.daemon_address);
    auto daemon_host = command_line::get_arg(vm, opts.daemon_host);
    auto daemon_port = command_line::get_arg(vm, opts.daemon_port);
    auto device_name = command_line::get_arg(vm, opts.hw_device);
    auto device_derivation_path = command_line::get_arg(vm, opts.hw_device_derivation_path);
    auto daemon_ssl_private_key = command_line::get_arg(vm, opts.daemon_ssl_private_key);
    auto daemon_ssl_certificate = command_line::get_arg(vm, opts.daemon_ssl_certificate);
    auto daemon_ssl_ca_file = command_line::get_arg(vm, opts.daemon_ssl_ca_certificates);
    auto daemon_ssl_allowed_fingerprints = command_line::get_arg(vm, opts.daemon_ssl_allowed_fingerprints);
    auto daemon_ssl_allow_any_cert = command_line::get_arg(vm, opts.daemon_ssl_allow_any_cert);
    auto daemon_ssl = command_line::get_arg(vm, opts.daemon_ssl);

    // user specified CA file or fingeprints implies enabled SSL by default
    epee::net_utils::ssl_options_t ssl_options = epee::net_utils::ssl_support_t::e_ssl_support_enabled;
    if (command_line::get_arg(vm, opts.daemon_ssl_allow_any_cert))
      ssl_options.verification = epee::net_utils::ssl_verification_t::none;
    else if (!daemon_ssl_ca_file.empty() || !daemon_ssl_allowed_fingerprints.empty())
    {
      std::vector<std::vector<uint8_t>> ssl_allowed_fingerprints{ daemon_ssl_allowed_fingerprints.size() };
      std::transform(daemon_ssl_allowed_fingerprints.begin(), daemon_ssl_allowed_fingerprints.end(), ssl_allowed_fingerprints.begin(), epee::from_hex::vector);
      for (const auto &fpr: ssl_allowed_fingerprints)
      {
        THROW_WALLET_EXCEPTION_IF(fpr.size() != SSL_FINGERPRINT_SIZE, tools::error::wallet_internal_error,
            "SHA-256 fingerprint should be " BOOST_PP_STRINGIZE(SSL_FINGERPRINT_SIZE) " bytes long.");
      }

      ssl_options = epee::net_utils::ssl_options_t{
        std::move(ssl_allowed_fingerprints), std::move(daemon_ssl_ca_file)
      };

      if (command_line::get_arg(vm, opts.daemon_ssl_allow_chained))
        ssl_options.verification = epee::net_utils::ssl_verification_t::user_ca;
    }

    if (ssl_options.verification != epee::net_utils::ssl_verification_t::user_certificates || !command_line::is_arg_defaulted(vm, opts.daemon_ssl))
    {
      THROW_WALLET_EXCEPTION_IF(!epee::net_utils::ssl_support_from_string(ssl_options.support, daemon_ssl), tools::error::wallet_internal_error,
         tools::wallet2::tr("Invalid argument for ") + std::string(opts.daemon_ssl.name));
    }

    ssl_options.auth = epee::net_utils::ssl_authentication_t{
      std::move(daemon_ssl_private_key), std::move(daemon_ssl_certificate)
    };

    THROW_WALLET_EXCEPTION_IF(!daemon_address.empty() && !daemon_host.empty() && 0 != daemon_port,
        tools::error::wallet_internal_error, tools::wallet2::tr("can't specify daemon host or port more than once"));

    boost::optional<epee::net_utils::http::login> login{};
    if (command_line::has_arg(vm, opts.daemon_login))
    {
      auto parsed = tools::login::parse(
        command_line::get_arg(vm, opts.daemon_login), false, [password_prompter](bool verify) {
          return password_prompter("Daemon client password", verify);
        }
      );
      if (!parsed)
        return nullptr;

      login.emplace(std::move(parsed->username), std::move(parsed->password).password());
    }

    if (daemon_host.empty())
      daemon_host = "localhost";

    if (!daemon_port)
    {
      daemon_port = get_config(nettype).RPC_DEFAULT_PORT;
    }

    if (daemon_address.empty())
      daemon_address = std::string("http://") + daemon_host + ":" + std::to_string(daemon_port);

    {
      const boost::string_ref real_daemon = boost::string_ref{daemon_address}.substr(0, daemon_address.rfind(':'));

      /* If SSL or proxy is enabled, then a specific cert, CA or fingerprint must
         be specified. This is specific to the wallet. */
      const bool verification_required =
        ssl_options.verification != epee::net_utils::ssl_verification_t::none &&
        (ssl_options.support == epee::net_utils::ssl_support_t::e_ssl_support_enabled || use_proxy);

      THROW_WALLET_EXCEPTION_IF(
        verification_required && !ssl_options.has_strong_verification(real_daemon),
        tools::error::wallet_internal_error,
        tools::wallet2::tr("Enabling --") + std::string{use_proxy ? opts.proxy.name : opts.daemon_ssl.name} + tools::wallet2::tr(" requires --") +
          opts.daemon_ssl_ca_certificates.name + tools::wallet2::tr(" or --") + opts.daemon_ssl_allowed_fingerprints.name + tools::wallet2::tr(" or use of a .onion/.i2p domain")
      );
    }

    boost::asio::ip::tcp::endpoint proxy{};
    if (use_proxy)
    {
      namespace ip = boost::asio::ip;

      const auto proxy_address = command_line::get_arg(vm, opts.proxy);

      boost::string_ref proxy_port{proxy_address};
      boost::string_ref proxy_host = proxy_port.substr(0, proxy_port.rfind(":"));
      if (proxy_port.size() == proxy_host.size())
        proxy_host = "127.0.0.1";
      else
        proxy_port = proxy_port.substr(proxy_host.size() + 1);

      uint16_t port_value = 0;
      THROW_WALLET_EXCEPTION_IF(
        !epee::string_tools::get_xtype_from_string(port_value, std::string{proxy_port}),
        tools::error::wallet_internal_error,
        std::string{"Invalid port specified for --"} + opts.proxy.name
      );

      boost::system::error_code error{};
      proxy = ip::tcp::endpoint{ip::address::from_string(std::string{proxy_host}, error), port_value};
      THROW_WALLET_EXCEPTION_IF(bool(error), tools::error::wallet_internal_error, std::string{"Invalid IP address specified for --"} + opts.proxy.name);
    }

    boost::optional<bool> trusted_daemon;
    if (!command_line::is_arg_defaulted(vm, opts.trusted_daemon) || !command_line::is_arg_defaulted(vm, opts.untrusted_daemon))
      trusted_daemon = command_line::get_arg(vm, opts.trusted_daemon) && !command_line::get_arg(vm, opts.untrusted_daemon);
    THROW_WALLET_EXCEPTION_IF(!command_line::is_arg_defaulted(vm, opts.trusted_daemon) && !command_line::is_arg_defaulted(vm, opts.untrusted_daemon),
      tools::error::wallet_internal_error, tools::wallet2::tr("--trusted-daemon and --untrusted-daemon are both seen, assuming untrusted"));

    // set --trusted-daemon if local and not overridden
    if (!trusted_daemon)
    {
      try
      {
        trusted_daemon = false;
        if (tools::is_local_address(daemon_address))
        {
          MINFO(tools::wallet2::tr("Daemon is local, assuming trusted"));
          trusted_daemon = true;
        }
      }
      catch (const std::exception &e) { }
    }

    std::unique_ptr<tools::wallet2> wallet(new tools::wallet2(nettype, kdf_rounds, unattended));
    wallet->init(std::move(daemon_address), std::move(login), std::move(proxy), 0, *trusted_daemon, std::move(ssl_options));
    boost::filesystem::path ringdb_path = command_line::get_arg(vm, opts.shared_ringdb_dir);
    wallet->set_ring_database(ringdb_path.string());
    wallet->get_message_store().set_options(vm);
    wallet->device_name(device_name);
    wallet->device_derivation_path(device_derivation_path);

    if (command_line::get_arg(vm, opts.no_dns))
      wallet->enable_dns(false);

    if (command_line::get_arg(vm, opts.offline))
      wallet->set_offline();

    const std::string extra_entropy = command_line::get_arg(vm, opts.extra_entropy);
    if (!extra_entropy.empty())
    {
      std::string data;
      THROW_WALLET_EXCEPTION_IF(!epee::file_io_utils::load_file_to_string(extra_entropy, data),
          tools::error::wallet_internal_error, "Failed to load extra entropy from " + extra_entropy);
      add_extra_entropy_thread_safe(data.data(), data.size());
    }

    try
    {
      if (!command_line::is_arg_defaulted(vm, opts.tx_notify))
        wallet->set_tx_notify(std::shared_ptr<tools::Notify>(new tools::Notify(command_line::get_arg(vm, opts.tx_notify).c_str())));
    }
    catch (const std::exception &e)
    {
      MERROR("Failed to parse tx notify spec: " << e.what());
    }

    return wallet;
  }

  boost::optional<tools::password_container> get_password(const boost::program_options::variables_map& vm, const options& opts, const std::function<boost::optional<tools::password_container>(const char*, bool)> &password_prompter, const bool verify)
  {
    if (command_line::has_arg(vm, opts.password) && command_line::has_arg(vm, opts.password_file))
    {
      THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("can't specify more than one of --password and --password-file"));
    }

    if (command_line::has_arg(vm, opts.password))
    {
      return tools::password_container{command_line::get_arg(vm, opts.password)};
    }

    if (command_line::has_arg(vm, opts.password_file))
    {
      std::string password;
      bool r = epee::file_io_utils::load_file_to_string(command_line::get_arg(vm, opts.password_file),
                                                        password);
      THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, tools::wallet2::tr("the password file specified could not be read"));

      // Remove line breaks the user might have inserted
      boost::trim_right_if(password, boost::is_any_of("\r\n"));
      return {tools::password_container{std::move(password)}};
    }

    THROW_WALLET_EXCEPTION_IF(!password_prompter, tools::error::wallet_internal_error, tools::wallet2::tr("no password specified; use --prompt-for-password to prompt for a password"));

    return password_prompter(verify ? tools::wallet2::tr("Enter a new password for the wallet") : tools::wallet2::tr("Wallet password"), verify);
  }

  std::pair<std::unique_ptr<tools::wallet2>, tools::password_container> generate_from_json(const std::string& json_file, const boost::program_options::variables_map& vm, bool unattended, const options& opts, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
  {
    const bool testnet = command_line::get_arg(vm, opts.testnet);
    const bool stagenet = command_line::get_arg(vm, opts.stagenet);
    const network_type nettype = testnet ? TESTNET : stagenet ? STAGENET : MAINNET;

    /* GET_FIELD_FROM_JSON_RETURN_ON_ERROR Is a generic macro that can return
    false. Gcc will coerce this into unique_ptr(nullptr), but clang correctly
    fails. This large wrapper is for the use of that macro */
    std::unique_ptr<tools::wallet2> wallet;
    epee::wipeable_string password;
    const auto do_generate = [&]() -> bool {
      std::string buf;
      if (!epee::file_io_utils::load_file_to_string(json_file, buf)) {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, std::string(tools::wallet2::tr("Failed to load file ")) + json_file);
        return false;
      }

      rapidjson::Document json;
      if (json.Parse(buf.c_str()).HasParseError()) {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Failed to parse JSON"));
        return false;
      }

      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, version, unsigned, Uint, true, 0);
      const int current_version = 1;
      THROW_WALLET_EXCEPTION_IF(field_version > current_version, tools::error::wallet_internal_error,
        ((boost::format(tools::wallet2::tr("Version %u too new, we can only grok up to %u")) % field_version % current_version)).str());

      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, filename, std::string, String, true, std::string());

      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, scan_from_height, uint64_t, Uint64, false, 0);
      const bool recover = true;

      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, password, std::string, String, false, std::string());

      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, viewkey, std::string, String, false, std::string());
      crypto::secret_key viewkey;
      if (field_viewkey_found)
      {
        cryptonote::blobdata viewkey_data;
        if(!epee::string_tools::parse_hexstr_to_binbuff(field_viewkey, viewkey_data) || viewkey_data.size() != sizeof(crypto::secret_key))
        {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to parse view key secret key"));
        }
        viewkey = *reinterpret_cast<const crypto::secret_key*>(viewkey_data.data());
        crypto::public_key pkey;
        if (!crypto::secret_key_to_public_key(viewkey, pkey)) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify view key secret key"));
        }
      }

      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, spendkey, std::string, String, false, std::string());
      crypto::secret_key spendkey;
      if (field_spendkey_found)
      {
        cryptonote::blobdata spendkey_data;
        if(!epee::string_tools::parse_hexstr_to_binbuff(field_spendkey, spendkey_data) || spendkey_data.size() != sizeof(crypto::secret_key))
        {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to parse spend key secret key"));
        }
        spendkey = *reinterpret_cast<const crypto::secret_key*>(spendkey_data.data());
        crypto::public_key pkey;
        if (!crypto::secret_key_to_public_key(spendkey, pkey)) {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify spend key secret key"));
        }
      }

      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed, std::string, String, false, std::string());
      std::string old_language;
      crypto::secret_key recovery_key;
      bool restore_deterministic_wallet = false;
      if (field_seed_found)
      {
        if (!crypto::ElectrumWords::words_to_bytes(field_seed, recovery_key, old_language))
        {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Electrum-style word list failed verification"));
        }
        restore_deterministic_wallet = true;

        GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, seed_passphrase, std::string, String, false, std::string());
        if (field_seed_passphrase_found)
        {
          if (!field_seed_passphrase.empty())
            recovery_key = cryptonote::decrypt_key(recovery_key, field_seed_passphrase);
        }
      }

      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, address, std::string, String, false, std::string());

      GET_FIELD_FROM_JSON_RETURN_ON_ERROR(json, create_address_file, int, Int, false, false);
      bool create_address_file = field_create_address_file;

      // compatibility checks
      if (!field_seed_found && !field_viewkey_found && !field_spendkey_found)
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("At least one of either an Electrum-style word list, private view key, or private spend key must be specified"));
      }
      if (field_seed_found && (field_viewkey_found || field_spendkey_found))
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Both Electrum-style word list and private key(s) specified"));
      }

      // if an address was given, we check keys against it, and deduce the spend
      // public key if it was not given
      if (field_address_found)
      {
        cryptonote::address_parse_info info;
        if(!get_account_address_from_str(info, nettype, field_address))
        {
          THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("invalid address"));
        }
        if (field_viewkey_found)
        {
          crypto::public_key pkey;
          if (!crypto::secret_key_to_public_key(viewkey, pkey)) {
            THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify view key secret key"));
          }
          if (info.address.m_view_public_key != pkey) {
            THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("view key does not match standard address"));
          }
        }
        if (field_spendkey_found)
        {
          crypto::public_key pkey;
          if (!crypto::secret_key_to_public_key(spendkey, pkey)) {
            THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify spend key secret key"));
          }
          if (info.address.m_spend_public_key != pkey) {
            THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("spend key does not match standard address"));
          }
        }
      }

      const bool deprecated_wallet = restore_deterministic_wallet && ((old_language == crypto::ElectrumWords::old_language_name) ||
        crypto::ElectrumWords::get_is_old_style_seed(field_seed));
      THROW_WALLET_EXCEPTION_IF(deprecated_wallet, tools::error::wallet_internal_error,
        tools::wallet2::tr("Cannot generate deprecated wallets from JSON"));

      wallet.reset(make_basic(vm, unattended, opts, password_prompter).release());
      wallet->set_refresh_from_block_height(field_scan_from_height);
      wallet->explicit_refresh_from_block_height(field_scan_from_height_found);
      if (!old_language.empty())
        wallet->set_seed_language(old_language);

      try
      {
        if (!field_seed.empty())
        {
          wallet->generate(field_filename, field_password, recovery_key, recover, false, create_address_file);
          password = field_password;
        }
        else if (field_viewkey.empty() && !field_spendkey.empty())
        {
          wallet->generate(field_filename, field_password, spendkey, recover, false, create_address_file);
          password = field_password;
        }
        else
        {
          cryptonote::account_public_address address;
          if (!crypto::secret_key_to_public_key(viewkey, address.m_view_public_key)) {
            THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify view key secret key"));
          }

          if (field_spendkey.empty())
          {
            // if we have an address but no spend key, we can deduce the spend public key
            // from the address
            if (field_address_found)
            {
              cryptonote::address_parse_info info;
              if(!get_account_address_from_str(info, nettype, field_address))
              {
                THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, std::string(tools::wallet2::tr("failed to parse address: ")) + field_address);
              }
              address.m_spend_public_key = info.address.m_spend_public_key;
            }
            else
            {
              THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("Address must be specified in order to create watch-only wallet"));
            }
            wallet->generate(field_filename, field_password, address, viewkey, create_address_file);
            password = field_password;
          }
          else
          {
            if (!crypto::secret_key_to_public_key(spendkey, address.m_spend_public_key)) {
              THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, tools::wallet2::tr("failed to verify spend key secret key"));
            }
            wallet->generate(field_filename, field_password, address, spendkey, viewkey, create_address_file);
            password = field_password;
          }
        }
      }
      catch (const std::exception& e)
      {
        THROW_WALLET_EXCEPTION(tools::error::wallet_internal_error, std::string(tools::wallet2::tr("failed to generate new wallet: ")) + e.what());
      }
      return true;
    };

    if (do_generate())
    {
      return {std::move(wallet), tools::password_container(password)};
    }
    return {nullptr, tools::password_container{}};
  }
}

namespace tools {

  bool wallet2::has_testnet_option(const boost::program_options::variables_map& vm)
  {
    return command_line::get_arg(vm, options().testnet);
  }

  bool wallet2::has_stagenet_option(const boost::program_options::variables_map& vm)
  {
    return command_line::get_arg(vm, options().stagenet);
  }

  std::string wallet2::device_name_option(const boost::program_options::variables_map& vm)
  {
    return command_line::get_arg(vm, options().hw_device);
  }

  std::string wallet2::device_derivation_path_option(const boost::program_options::variables_map &vm)
  {
    return command_line::get_arg(vm, options().hw_device_derivation_path);
  }

  void wallet2::init_options(boost::program_options::options_description& desc_params)
  {
    const options opts{};
    command_line::add_arg(desc_params, opts.daemon_address);
    command_line::add_arg(desc_params, opts.daemon_host);
    command_line::add_arg(desc_params, opts.proxy);
    command_line::add_arg(desc_params, opts.trusted_daemon);
    command_line::add_arg(desc_params, opts.untrusted_daemon);
    command_line::add_arg(desc_params, opts.password);
    command_line::add_arg(desc_params, opts.password_file);
    command_line::add_arg(desc_params, opts.daemon_port);
    command_line::add_arg(desc_params, opts.daemon_login);
    command_line::add_arg(desc_params, opts.daemon_ssl);
    command_line::add_arg(desc_params, opts.daemon_ssl_private_key);
    command_line::add_arg(desc_params, opts.daemon_ssl_certificate);
    command_line::add_arg(desc_params, opts.daemon_ssl_ca_certificates);
    command_line::add_arg(desc_params, opts.daemon_ssl_allowed_fingerprints);
    command_line::add_arg(desc_params, opts.daemon_ssl_allow_any_cert);
    command_line::add_arg(desc_params, opts.daemon_ssl_allow_chained);
    command_line::add_arg(desc_params, opts.testnet);
    command_line::add_arg(desc_params, opts.stagenet);
    command_line::add_arg(desc_params, opts.shared_ringdb_dir);
    command_line::add_arg(desc_params, opts.kdf_rounds);
    mms::message_store::init_options(desc_params);
    command_line::add_arg(desc_params, opts.hw_device);
    command_line::add_arg(desc_params, opts.hw_device_derivation_path);
    command_line::add_arg(desc_params, opts.tx_notify);
    command_line::add_arg(desc_params, opts.no_dns);
    command_line::add_arg(desc_params, opts.offline);
    command_line::add_arg(desc_params, opts.extra_entropy);
  }

  std::pair<std::unique_ptr<wallet2>, tools::password_container> wallet2::make_from_json(const boost::program_options::variables_map& vm, bool unattended, const std::string& json_file, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
  {
    const options opts{};
    return generate_from_json(json_file, vm, unattended, opts, password_prompter);
  }

  std::pair<std::unique_ptr<wallet2>, password_container> wallet2::make_from_file(
    const boost::program_options::variables_map& vm, bool unattended, const std::string& wallet_file, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
  {
    const options opts{};
    auto pwd = get_password(vm, opts, password_prompter, false);
    if (!pwd)
    {
      return {nullptr, password_container{}};
    }
    auto wallet = make_basic(vm, unattended, opts, password_prompter);
    if (wallet && !wallet_file.empty())
    {
      wallet->load(wallet_file, pwd->password());
    }
    return {std::move(wallet), std::move(*pwd)};
  }

  std::pair<std::unique_ptr<wallet2>, password_container> wallet2::make_new(const boost::program_options::variables_map& vm, bool unattended, const std::function<boost::optional<password_container>(const char *, bool)> &password_prompter)
  {
    const options opts{};
    auto pwd = get_password(vm, opts, password_prompter, true);
    if (!pwd)
    {
      return {nullptr, password_container{}};
    }
    return {make_basic(vm, unattended, opts, password_prompter), std::move(*pwd)};
  }

  std::unique_ptr<wallet2> wallet2::make_dummy(const boost::program_options::variables_map& vm, bool unattended, const std::function<boost::optional<tools::password_container>(const char *, bool)> &password_prompter)
  {
    const options opts{};
    return make_basic(vm, unattended, opts, password_prompter);
  }

  wallet2::~wallet2()
  {
  }
}
