// legacy dump format (implementation)
// Copyright 2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg-tool/legacy_dump.h>

#include <neopg/v3_public_key_data.h>
#include <neopg/v4_public_key_data.h>

#include <neopg/dsa_public_key_material.h>
#include <neopg/ecdh_public_key_material.h>
#include <neopg/ecdsa_public_key_material.h>
#include <neopg/eddsa_public_key_material.h>
#include <neopg/elgamal_public_key_material.h>
#include <neopg/raw_public_key_material.h>
#include <neopg/rsa_public_key_material.h>

#include <neopg/dsa_public_key_material.h>
#include <neopg/ecdh_public_key_material.h>
#include <neopg/ecdsa_public_key_material.h>
#include <neopg/eddsa_public_key_material.h>
#include <neopg/elgamal_public_key_material.h>
#include <neopg/rsa_public_key_material.h>

#include <neopg/v3_signature_data.h>
#include <neopg/v4_signature_data.h>

#include <neopg/embedded_signature_subpacket.h>
#include <neopg/exportable_certification_subpacket.h>
#include <neopg/features_subpacket.h>
#include <neopg/issuer_subpacket.h>
#include <neopg/key_expiration_time_subpacket.h>
#include <neopg/key_flags_subpacket.h>
#include <neopg/key_server_preferences_subpacket.h>
#include <neopg/notation_data_subpacket.h>
#include <neopg/policy_uri_subpacket.h>
#include <neopg/preferred_compression_algorithms_subpacket.h>
#include <neopg/preferred_hash_algorithms_subpacket.h>
#include <neopg/preferred_key_server_subpacket.h>
#include <neopg/preferred_symmetric_algorithms_subpacket.h>
#include <neopg/primary_user_id_subpacket.h>
#include <neopg/reason_for_revocation_subpacket.h>
#include <neopg/regular_expression_subpacket.h>
#include <neopg/revocable_subpacket.h>
#include <neopg/revocation_key_subpacket.h>
#include <neopg/signature_creation_time_subpacket.h>
#include <neopg/signature_expiration_time_subpacket.h>
#include <neopg/signature_target_subpacket.h>
#include <neopg/signers_user_id_subpacket.h>
#include <neopg/trust_signature_subpacket.h>

#include <neopg/dsa_signature_material.h>
#include <neopg/ecdsa_signature_material.h>
#include <neopg/eddsa_signature_material.h>
#include <neopg/raw_signature_material.h>
#include <neopg/rsa_signature_material.h>

#include <neopg/image_attribute_subpacket.h>

#include <botan/data_snk.h>
#include <botan/data_src.h>
#include <botan/hex.h>

#include <botan/ber_dec.h>
#include <botan/oids.h>

#include <CLI11.hpp>

#include <spdlog/fmt/fmt.h>

#include <rang.hpp>

#include <tao/json.hpp>

#include <iostream>

using namespace NeoPG;

static void output_header(std::ostream& out, const PacketHeader* header) {
  std::stringstream head_ss;
  header->write(head_ss);
  auto head = head_ss.str();

  auto new_header = dynamic_cast<const NewPacketHeader*>(header);

  // Example output:
  // # off=0 ctb=99 tag=6 hlen=3 plen=525
  // # off=229725 ctb=d1 tag=17 hlen=6 plen=3033 new-ctb
  out << rang::fg::gray << "# off=" << header->m_offset
      << " ctb=" << fmt::format("{:02x}", static_cast<int>((uint8_t)head[0]))
      << " tag=" << (int)header->type() << " hlen=" << head.length()
      << " plen=" << header->length() << (new_header ? " new-ctb" : "")
      << rang::style::reset << "\n";
}

static void output_public_key_data(std::ostream& out,
                                   const PublicKeyData* pub) {
  PublicKeyMaterial* key = nullptr;
  switch (pub->version()) {
    case PublicKeyVersion::V2:
    case PublicKeyVersion::V3: {
      auto v3pub = dynamic_cast<const V3PublicKeyData*>(pub);
      out << "\tversion " << static_cast<int>(pub->version()) << ", algo "
          << static_cast<int>(v3pub->m_algorithm) << ", created "
          << v3pub->m_created << ", expires " << v3pub->m_days_valid << "\n";
      key = v3pub->m_key.get();
    } break;
    case PublicKeyVersion::V4: {
      auto v4pub = dynamic_cast<const V4PublicKeyData*>(pub);
      out << "\tversion " << static_cast<int>(pub->version()) << ", algo "
          << static_cast<int>(v4pub->m_algorithm) << ", created "
          << v4pub->m_created << ", expires 0"
          << "\n";
      key = v4pub->m_key.get();
    } break;
    default:
      out << "\tversion " << static_cast<int>(pub->version()) << "\n";
      break;
  }
  if (key) {
    switch (key->algorithm()) {
      case PublicKeyAlgorithm::Rsa: {
        auto rsa = dynamic_cast<const RsaPublicKeyMaterial*>(key);
        out << "\tpkey[0]: [" << rsa->m_n.length() << " bits]\n";
        out << "\tpkey[1]: [" << rsa->m_e.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Dsa: {
        auto dsa = dynamic_cast<const DsaPublicKeyMaterial*>(key);
        out << "\tpkey[0]: [" << dsa->m_p.length() << " bits]\n";
        out << "\tpkey[1]: [" << dsa->m_q.length() << " bits]\n";
        out << "\tpkey[2]: [" << dsa->m_g.length() << " bits]\n";
        out << "\tpkey[3]: [" << dsa->m_y.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Elgamal: {
        auto elgamal = dynamic_cast<const ElgamalPublicKeyMaterial*>(key);
        out << "\tpkey[0]: [" << elgamal->m_p.length() << " bits]\n";
        out << "\tpkey[1]: [" << elgamal->m_g.length() << " bits]\n";
        out << "\tpkey[2]: [" << elgamal->m_y.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Ecdsa: {
        auto ecdsa = dynamic_cast<const EcdsaPublicKeyMaterial*>(key);
        const std::string oidstr = ecdsa->m_curve.as_string();
        Botan::OID oid(oidstr);
        out << "\tpkey[0]: [" << (1 + ecdsa->m_curve.length()) * 8 << " bits] "
            << Botan::OIDS::lookup(oid) << " (" << oidstr << ")\n";
        out << "\tpkey[1]: [" << ecdsa->m_key.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Eddsa: {
        auto eddsa = dynamic_cast<const EddsaPublicKeyMaterial*>(key);
        const std::string oidstr = eddsa->m_curve.as_string();
        Botan::OID oid(oidstr);
        out << "\tpkey[0]: [" << (1 + eddsa->m_curve.length()) * 8 << " bits] "
            << Botan::OIDS::lookup(oid) << " (" << oidstr << ")\n";
        out << "\tpkey[1]: [" << eddsa->m_key.length() << " bits]\n";
      } break;
      default:
        out << "\tunknown algorithm " << static_cast<int>(key->algorithm())
            << "\n";
        break;
    }
    auto keyid = pub->keyid();
    out << "\tkeyid: " << Botan::hex_encode(keyid.data(), keyid.size()) << "\n";
  }
}

static void output_signature_subpacket(std::ostream& out,
                                       const std::string& variant,
                                       SignatureSubpacket* subpacket) {
  out << "\t" << (subpacket->m_critical ? "critical " : "") << variant << " "
      << static_cast<int>(subpacket->type()) << " len "
      << subpacket->body_length();
  switch (subpacket->type()) {
    case SignatureSubpacketType::SignatureCreationTime: {
      auto sub = dynamic_cast<const SignatureCreationTimeSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (sig created " << sub->m_created << ")";
      break;
    }
    case SignatureSubpacketType::SignatureExpirationTime: {
      auto sub =
          dynamic_cast<const SignatureExpirationTimeSubpacket*>(subpacket);
      assert(sub != nullptr);
      if (sub->m_expiration)
        out << " (sig expires after " << sub->m_expiration << ")";
      else
        out << " (sig does not expire)";
      break;
    }
    case SignatureSubpacketType::ExportableCertification: {
      auto sub =
          dynamic_cast<const ExportableCertificationSubpacket*>(subpacket);
      assert(sub != nullptr);
      if (sub->m_exportable)
        out << " (exportable)";
      else
        out << " (not exportable)";
      break;
    }
    case SignatureSubpacketType::TrustSignature: {
      auto sub = dynamic_cast<const TrustSignatureSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (trust signature of depth " << (int)sub->m_level << ", value "
          << (int)sub->m_amount << ")";
      break;
    }
    case SignatureSubpacketType::RegularExpression: {
      auto sub = dynamic_cast<const RegularExpressionSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_regex;
      out << " (regular expression: " << str << ")";
      break;
    }
    case SignatureSubpacketType::Revocable: {
      auto sub = dynamic_cast<const RevocableSubpacket*>(subpacket);
      assert(sub != nullptr);
      if (sub->m_revocable)
        out << " (revocable)";
      else
        out << " (not revocable)";
      break;
    }
    case SignatureSubpacketType::KeyExpirationTime: {
      auto sub = dynamic_cast<const KeyExpirationTimeSubpacket*>(subpacket);
      assert(sub != nullptr);
      if (sub->m_expiration) {
        int seconds = sub->m_expiration;
        int minutes = seconds / 60;
        int hours = minutes / 60;
        int days = hours / 24;
        int years = days / 365;
        out << " (key expires after " << years << "y" << (days % 365) << "d"
            << (hours % 24) << "h" << (minutes % 60) << "m)";
      } else
        out << " (key does not expire)";
      break;
    }
    case SignatureSubpacketType::PreferredSymmetricAlgorithms: {
      auto sub =
          dynamic_cast<const PreferredSymmetricAlgorithmsSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (pref-sym-algos:";
      for (auto& algorithm : sub->m_algorithms) out << " " << (int)algorithm;
      out << ")";
      break;
    }
    case SignatureSubpacketType::RevocationKey: {
      auto sub = dynamic_cast<const RevocationKeySubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (revocation key: c="
          << fmt::format("{:02x}", static_cast<int>(sub->m_class))
          << " a=" << static_cast<int>(sub->m_algorithm) << " f="
          << Botan::hex_encode(sub->m_fingerprint.data(),
                               sub->m_fingerprint.size())
          << ")";
      break;
    }
    case SignatureSubpacketType::Issuer: {
      auto sub = dynamic_cast<const IssuerSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (issuer key ID "
          << Botan::hex_encode(sub->m_issuer.data(), sub->m_issuer.size())
          << ")";
      break;
    }
    case SignatureSubpacketType::NotationData: {
      auto sub = dynamic_cast<const NotationDataSubpacket*>(subpacket);
      assert(sub != nullptr);
      // FIXME: Avoid copy?
      const tao::json::value name =
          std::string{reinterpret_cast<const char*>(sub->m_name.data()),
                      sub->m_name.size()};
      const tao::json::value value =
          std::string{reinterpret_cast<const char*>(sub->m_value.data()),
                      sub->m_value.size()};
      out << " (notation: " << name << " = " << value << ")";
      break;
    }
    case SignatureSubpacketType::PreferredHashAlgorithms: {
      auto sub =
          dynamic_cast<const PreferredHashAlgorithmsSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (pref-hash-algos:";
      for (auto& algorithm : sub->m_algorithms) out << " " << (int)algorithm;
      out << ")";
      break;
    }
    case SignatureSubpacketType::PreferredCompressionAlgorithms: {
      auto sub = dynamic_cast<const PreferredCompressionAlgorithmsSubpacket*>(
          subpacket);
      assert(sub != nullptr);
      out << " (pref-zip-algos:";
      for (auto& algorithm : sub->m_algorithms) out << " " << (int)algorithm;
      out << ")";
      break;
    }
    case SignatureSubpacketType::KeyServerPreferences: {
      auto sub = dynamic_cast<const KeyServerPreferencesSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (keyserver preferences: "
          << Botan::hex_encode(sub->m_flags.data(), sub->m_flags.size()) << ")";
      break;
    }
    case SignatureSubpacketType::PreferredKeyServer: {
      auto sub = dynamic_cast<const PreferredKeyServerSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_uri;
      out << " (preferred keyserver: " << str << ")";
      break;
    }
    case SignatureSubpacketType::PrimaryUserId: {
      auto sub = dynamic_cast<const PrimaryUserIdSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (primary user ID: "
          << fmt::format("{:02x}", static_cast<int>(sub->m_primary)) << ")";
      break;
    }
    case SignatureSubpacketType::PolicyUri: {
      auto sub = dynamic_cast<const PolicyUriSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_uri;
      out << " (policy: " << str << ")";
      break;
    }
    case SignatureSubpacketType::KeyFlags: {
      auto sub = dynamic_cast<const KeyFlagsSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (key flags: "
          << Botan::hex_encode(sub->m_flags.data(), sub->m_flags.size()) << ")";
      break;
    }
    case SignatureSubpacketType::SignersUserId: {
      auto sub = dynamic_cast<const SignersUserIdSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_user_id;
      out << " (signer's user ID: " << str << ")";
      break;
    }
    case SignatureSubpacketType::ReasonForRevocation: {
      auto sub = dynamic_cast<const ReasonForRevocationSubpacket*>(subpacket);
      assert(sub != nullptr);
      const tao::json::value str = sub->m_reason;
      out << " (revocation reason 0x"
          << fmt::format("{:02x}", static_cast<int>(sub->m_code)) << " " << str
          << ")";
      break;
    }
    case SignatureSubpacketType::Features: {
      auto sub = dynamic_cast<const FeaturesSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << " (features: "
          << Botan::hex_encode(sub->m_features.data(), sub->m_features.size())
          << ")";
      break;
    }
    case SignatureSubpacketType::SignatureTarget: {
      auto sub = dynamic_cast<const SignatureTargetSubpacket*>(subpacket);
      assert(sub != nullptr);
      out << fmt::format(
                 " (signature target: pubkey_algo {:d}, digest algo "
                 "{:d}), digest ",
                 static_cast<uint8_t>(sub->m_public_key_algorithm),
                 static_cast<uint8_t>(sub->m_hash_algorithm))
          << Botan::hex_encode(sub->m_hash.data(), sub->m_hash.size()) << ")";
      break;
    }
    case SignatureSubpacketType::EmbeddedSignature: {
      auto sub = dynamic_cast<const EmbeddedSignatureSubpacket*>(subpacket);
      assert(sub != nullptr);
      ParserInput in(sub->m_signature.data(), sub->m_signature.size());
      auto sig = SignaturePacket::create(in);

      if (sig == nullptr || !sig->m_signature)
        out << " (signature: invalid)";
      else {
        switch (sig->m_signature->version()) {
          case SignatureVersion::V2:
          case SignatureVersion::V3: {
            auto v3sig =
                dynamic_cast<const V3SignatureData*>(sig->m_signature.get());
            assert(v3sig != nullptr);
            out << fmt::format(
                " (signature: v{:d}, class 0x{:02x}, algo {:d}, digest algo "
                "{:d})",
                static_cast<uint8_t>(v3sig->version()),
                static_cast<uint8_t>(v3sig->signature_type()),
                static_cast<uint8_t>(v3sig->public_key_algorithm()),
                static_cast<uint8_t>(v3sig->hash_algorithm()));
            break;
          }
          case SignatureVersion::V4: {
            auto v4sig =
                dynamic_cast<const V4SignatureData*>(sig->m_signature.get());
            assert(v4sig != nullptr);
            out << fmt::format(
                " (signature: v{:d}, class 0x{:02x}, algo {:d}, digest algo "
                "{:d})",
                static_cast<uint8_t>(v4sig->version()),
                static_cast<uint8_t>(v4sig->signature_type()),
                static_cast<uint8_t>(v4sig->public_key_algorithm()),
                static_cast<uint8_t>(v4sig->hash_algorithm()));
            break;
          }
          default:
            out << fmt::format(" (signature: v{:d})",
                               static_cast<uint8_t>(sig->version()));
            break;
        }
      }
      break;
    }
    default:
      break;
  }
  out << "\n";
}

static void output_signature_data(std::ostream& out, const SignatureData* sig) {
  const SignatureMaterial* sigmat = nullptr;
  switch (sig->version()) {
    case SignatureVersion::V2:
    case SignatureVersion::V3: {
      auto v3sig = dynamic_cast<const V3SignatureData*>(sig);
      assert(v3sig != nullptr);
      out << ":signature packet: algo "
          << static_cast<int>(v3sig->public_key_algorithm()) << "\n";
      out << "\tversion 3, created " << v3sig->m_created
          << ", md5len 5, sigclass 0x"
          << fmt::format("{:02x}", static_cast<int>(v3sig->signature_type()))
          << "\n";
      out << "\tdigest algo " << static_cast<int>(v3sig->hash_algorithm())
          << ", begin of digest "
          << fmt::format("{:02x}", static_cast<int>(v3sig->m_quick.data()[0]))
          << " "
          << fmt::format("{:02x}", static_cast<int>(v3sig->m_quick.data()[1]))
          << "\n";
      sigmat = v3sig->m_signature.get();
    } break;
    case SignatureVersion::V4: {
      auto v4sig = dynamic_cast<const V4SignatureData*>(sig);
      assert(v4sig != nullptr);
      // FIXME: Try to get created from subpackets.
      out << ":signature packet: algo "
          << static_cast<int>(v4sig->public_key_algorithm()) << "\n";
      out << "\tversion 4, created " << v4sig->m_created
          << ", md5len 0, sigclass 0x"
          << fmt::format("{:02x}", static_cast<int>(v4sig->signature_type()))
          << "\n";
      out << "\tdigest algo " << static_cast<int>(v4sig->hash_algorithm())
          << ", begin of digest "
          << fmt::format("{:02x}", static_cast<int>(v4sig->m_quick.data()[0]))
          << " "
          << fmt::format("{:02x}", static_cast<int>(v4sig->m_quick.data()[1]))
          << "\n";
      for (auto& subpacket : v4sig->m_hashed_subpackets->m_subpackets) {
        output_signature_subpacket(out, "hashed subpkt", subpacket.get());
      }
      for (auto& subpacket : v4sig->m_unhashed_subpackets->m_subpackets) {
        output_signature_subpacket(out, "subpkt", subpacket.get());
      }
      sigmat = v4sig->m_signature.get();
    } break;
    default:
      break;
  }
  if (sigmat) {
    switch (sigmat->algorithm()) {
      case PublicKeyAlgorithm::Rsa: {
        auto rsa = dynamic_cast<const RsaSignatureMaterial*>(sigmat);
        out << "\tdata: [" << rsa->m_m_pow_d.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Dsa: {
        auto dsa = dynamic_cast<const DsaSignatureMaterial*>(sigmat);
        out << "\tdata: [" << dsa->m_r.length() << " bits]\n";
        out << "\tdata: [" << dsa->m_s.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Ecdsa: {
        auto ecdsa = dynamic_cast<const EcdsaSignatureMaterial*>(sigmat);
        out << "\tdata: [" << ecdsa->m_r.length() << " bits]\n";
        out << "\tdata: [" << ecdsa->m_s.length() << " bits]\n";
      } break;
      case PublicKeyAlgorithm::Eddsa: {
        auto eddsa = dynamic_cast<const EddsaSignatureMaterial*>(sigmat);
        out << "\tdata: [" << eddsa->m_r.length() << " bits]\n";
        out << "\tdata: [" << eddsa->m_s.length() << " bits]\n";
      } break;
      default:
        out << "\tunknown algorithm " << static_cast<int>(sigmat->algorithm())
            << "\n";
        break;
    }
  }
}

void LegacyDump::dump(const Packet* packet) const {
  output_header(m_out, packet->m_header.get());
  DumpPacketSink::dump(packet);
}

void LegacyDump::dump(const MarkerPacket* packet) const {
  m_out << ":marker packet: PGP\n";
}

void LegacyDump::dump(const UserIdPacket* uid) const {
  const tao::json::value str = uid->m_content;
  m_out << fmt::format(":user ID packet: {:s}\n", tao::json::to_string(str));
}

void LegacyDump::dump(const UserAttributePacket* attr) const {
  m_out << ":attribute packet:\n";
  for (const auto& sub : attr->m_subpackets) {
    switch (sub->type()) {
      case UserAttributeSubpacketType::Image: {
        auto img = dynamic_cast<const ImageAttributeSubpacket*>(sub.get());
        assert(img != nullptr);
        m_out << fmt::format("\t[image {:d} of size {:d}]\n",
                             static_cast<uint8_t>(img->m_encoding),
                             img->m_image.size());
      } break;
      default:
        m_out << fmt::format("\t[unknown type {:d} of size {:d}]\n",
                             static_cast<uint8_t>(sub->type()),
                             sub->body_length());
    }
  }
}

void LegacyDump::dump(const PublicKeyPacket* pubkey) const {
  m_out << ":public key packet:\n";
  auto pub = dynamic_cast<const PublicKeyData*>(pubkey->m_public_key.get());
  assert(pub != nullptr);
  output_public_key_data(m_out, pub);
}

void LegacyDump::dump(const PublicSubkeyPacket* pubkey) const {
  m_out << ":public sub key packet:\n";
  auto pub = dynamic_cast<const PublicKeyData*>(pubkey->m_public_key.get());
  assert(pub != nullptr);
  output_public_key_data(m_out, pub);
}

void LegacyDump::dump(const SignaturePacket* signature) const {
  auto sig = dynamic_cast<const SignatureData*>(signature->m_signature.get());
  assert(sig);
  output_signature_data(m_out, sig);
}
