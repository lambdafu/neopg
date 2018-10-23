// OpenPGP signature subpacket (implementation)
// Copyright 2017-2018 The NeoPG developers
//
// NeoPG is released under the Simplified BSD License (see license.txt)

#include <neopg/openpgp/signature/signature_subpacket.h>

#include <neopg/openpgp/signature/subpacket/embedded_signature_subpacket.h>
#include <neopg/openpgp/signature/subpacket/exportable_certification_subpacket.h>
#include <neopg/openpgp/signature/subpacket/features_subpacket.h>
#include <neopg/openpgp/signature/subpacket/issuer_subpacket.h>
#include <neopg/openpgp/signature/subpacket/key_expiration_time_subpacket.h>
#include <neopg/openpgp/signature/subpacket/key_flags_subpacket.h>
#include <neopg/openpgp/signature/subpacket/key_server_preferences_subpacket.h>
#include <neopg/openpgp/signature/subpacket/notation_data_subpacket.h>
#include <neopg/openpgp/signature/subpacket/policy_uri_subpacket.h>
#include <neopg/openpgp/signature/subpacket/preferred_compression_algorithms_subpacket.h>
#include <neopg/openpgp/signature/subpacket/preferred_hash_algorithms_subpacket.h>
#include <neopg/openpgp/signature/subpacket/preferred_key_server_subpacket.h>
#include <neopg/openpgp/signature/subpacket/preferred_symmetric_algorithms_subpacket.h>
#include <neopg/openpgp/signature/subpacket/primary_user_id_subpacket.h>
#include <neopg/openpgp/signature/subpacket/raw_signature_subpacket.h>
#include <neopg/openpgp/signature/subpacket/reason_for_revocation_subpacket.h>
#include <neopg/openpgp/signature/subpacket/regular_expression_subpacket.h>
#include <neopg/openpgp/signature/subpacket/revocable_subpacket.h>
#include <neopg/openpgp/signature/subpacket/revocation_key_subpacket.h>
#include <neopg/openpgp/signature/subpacket/signature_creation_time_subpacket.h>
#include <neopg/openpgp/signature/subpacket/signature_expiration_time_subpacket.h>
#include <neopg/openpgp/signature/subpacket/signature_target_subpacket.h>
#include <neopg/openpgp/signature/subpacket/signers_user_id_subpacket.h>
#include <neopg/openpgp/signature/subpacket/trust_signature_subpacket.h>

#include <neopg/parser/parser_input.h>
#include <neopg/utils/stream.h>

#include <neopg/intern/cplusplus.h>
#include <neopg/intern/pegtl.h>

using namespace NeoPG;

void SignatureSubpacketLength::verify_length(
    uint32_t length, SignatureSubpacketLengthType length_type) {
  if (length_type == SignatureSubpacketLengthType::OneOctet and
      not(length <= 0xbf)) {
    throw std::logic_error("Invalid packet length for one octet");
  } else if (length_type == SignatureSubpacketLengthType::TwoOctet and
             not(length >= 0xc0 and length <= 0x3fbf)) {
    throw std::logic_error("Invalid packet length for two octets");
  }
}

SignatureSubpacketLengthType SignatureSubpacketLength::best_length_type(
    uint32_t length) {
  if (length <= 0xbf)
    return SignatureSubpacketLengthType::OneOctet;
  else if (length <= 0x3fbf)
    return SignatureSubpacketLengthType::TwoOctet;
  else
    return SignatureSubpacketLengthType::FiveOctet;
}

void SignatureSubpacketLength::set_length(
    uint32_t length, SignatureSubpacketLengthType length_type) {
  verify_length(length, length_type);
  m_length_type = length_type;
  m_length = length;
}

SignatureSubpacketLength::SignatureSubpacketLength(
    uint32_t length, SignatureSubpacketLengthType length_type) {
  set_length(length, length_type);
}

void SignatureSubpacketLength::write(std::ostream& out) {
  SignatureSubpacketLengthType lentype = m_length_type;
  if (lentype == SignatureSubpacketLengthType::Default)
    lentype = best_length_type(m_length);

  switch (lentype) {
    case SignatureSubpacketLengthType::OneOctet:
      out << (uint8_t)m_length;
      break;

    case SignatureSubpacketLengthType::TwoOctet: {
      uint32_t adj_length = m_length - 0xc0;
      out << (uint8_t)(((adj_length >> 8) & 0x3f) + 0xc0)
          << ((uint8_t)(adj_length & 0xff));
    } break;

    case SignatureSubpacketLengthType::FiveOctet:
      out << (uint8_t)0xff << ((uint8_t)((m_length >> 24) & 0xff))
          << ((uint8_t)((m_length >> 16) & 0xff))
          << ((uint8_t)((m_length >> 8) & 0xff))
          << ((uint8_t)(m_length & 0xff));
      break;

    // LCOV_EXCL_START
    case SignatureSubpacketLengthType::Default:
      throw std::logic_error(
          "Unspecific signature subpacket length type (shouldn't happen).");
      // LCOV_EXCL_STOP
  }
}

std::unique_ptr<SignatureSubpacket> SignatureSubpacket::create_or_throw(
    SignatureSubpacketType type, ParserInput& in) {
  switch (type) {
    case SignatureSubpacketType::SignatureCreationTime:
      return SignatureCreationTimeSubpacket::create_or_throw(in);
    case SignatureSubpacketType::SignatureExpirationTime:
      return SignatureExpirationTimeSubpacket::create_or_throw(in);
    case SignatureSubpacketType::ExportableCertification:
      return ExportableCertificationSubpacket::create_or_throw(in);
    case SignatureSubpacketType::TrustSignature:
      return TrustSignatureSubpacket::create_or_throw(in);
    case SignatureSubpacketType::RegularExpression:
      return RegularExpressionSubpacket::create_or_throw(in);
    case SignatureSubpacketType::Revocable:
      return RevocableSubpacket::create_or_throw(in);
    case SignatureSubpacketType::KeyExpirationTime:
      return KeyExpirationTimeSubpacket::create_or_throw(in);
    case SignatureSubpacketType::PreferredSymmetricAlgorithms:
      return PreferredSymmetricAlgorithmsSubpacket::create_or_throw(in);
    case SignatureSubpacketType::RevocationKey:
      return RevocationKeySubpacket::create_or_throw(in);
    case SignatureSubpacketType::Issuer:
      return IssuerSubpacket::create_or_throw(in);
    case SignatureSubpacketType::NotationData:
      return NotationDataSubpacket::create_or_throw(in);
    case SignatureSubpacketType::PreferredHashAlgorithms:
      return PreferredHashAlgorithmsSubpacket::create_or_throw(in);
    case SignatureSubpacketType::PreferredCompressionAlgorithms:
      return PreferredCompressionAlgorithmsSubpacket::create_or_throw(in);
    case SignatureSubpacketType::KeyServerPreferences:
      return KeyServerPreferencesSubpacket::create_or_throw(in);
    case SignatureSubpacketType::PreferredKeyServer:
      return PreferredKeyServerSubpacket::create_or_throw(in);
    case SignatureSubpacketType::PrimaryUserId:
      return PrimaryUserIdSubpacket::create_or_throw(in);
    case SignatureSubpacketType::PolicyUri:
      return PolicyUriSubpacket::create_or_throw(in);
    case SignatureSubpacketType::KeyFlags:
      return KeyFlagsSubpacket::create_or_throw(in);
    case SignatureSubpacketType::SignersUserId:
      return SignersUserIdSubpacket::create_or_throw(in);
    case SignatureSubpacketType::ReasonForRevocation:
      return ReasonForRevocationSubpacket::create_or_throw(in);
    case SignatureSubpacketType::Features:
      return FeaturesSubpacket::create_or_throw(in);
    case SignatureSubpacketType::SignatureTarget:
      return SignatureTargetSubpacket::create_or_throw(in);
    case SignatureSubpacketType::EmbeddedSignature:
      return EmbeddedSignatureSubpacket::create_or_throw(in);
    default:
      return RawSignatureSubpacket::create_or_throw(type, in);
  }
}

uint32_t SignatureSubpacket::body_length() const {
  CountingStream cnt;
  write_body(cnt);
  return cnt.bytes_written();
}

void SignatureSubpacket::write(std::ostream& out,
                               SignatureSubpacketLengthType length_type) const {
  if (m_length) {
    m_length->write(out);
  } else {
    CountingStream cnt;
    write_body(cnt);
    uint32_t len = cnt.bytes_written();
    // Length needs to include the type octet.
    if (len == (uint32_t)-1)
      throw std::length_error("signature subpacket too large");
    len = len + 1;
    SignatureSubpacketLength default_length(len, length_type);
    default_length.write(out);
  }
  auto subpacket_type = static_cast<uint8_t>(type());
  if (critical()) subpacket_type |= 0x80_b;
  out << subpacket_type;
  write_body(out);
}
