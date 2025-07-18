// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// When writing a match expression against `KeyUsage`, it is important to ensure
/// your code is forward-compatible. That is, if a match arm handles a case for a
/// feature that is supported by the service but has not been represented as an enum
/// variant in a current version of SDK, your code should continue to work when you
/// upgrade SDK to a future version in which the enum does include a variant for that
/// feature.
///
/// Here is an example of how you can make a match expression forward-compatible:
///
/// ```text
/// # let keyusage = unimplemented!();
/// match keyusage {
///     KeyUsage::Tr31B0BaseDerivationKey => { /* ... */ },
///     KeyUsage::Tr31C0CardVerificationKey => { /* ... */ },
///     KeyUsage::Tr31D0SymmetricDataEncryptionKey => { /* ... */ },
///     KeyUsage::Tr31D1AsymmetricKeyForDataEncryption => { /* ... */ },
///     KeyUsage::Tr31E0EmvMkeyAppCryptograms => { /* ... */ },
///     KeyUsage::Tr31E1EmvMkeyConfidentiality => { /* ... */ },
///     KeyUsage::Tr31E2EmvMkeyIntegrity => { /* ... */ },
///     KeyUsage::Tr31E4EmvMkeyDynamicNumbers => { /* ... */ },
///     KeyUsage::Tr31E5EmvMkeyCardPersonalization => { /* ... */ },
///     KeyUsage::Tr31E6EmvMkeyOther => { /* ... */ },
///     KeyUsage::Tr31K0KeyEncryptionKey => { /* ... */ },
///     KeyUsage::Tr31K1KeyBlockProtectionKey => { /* ... */ },
///     KeyUsage::Tr31K2Tr34AsymmetricKey => { /* ... */ },
///     KeyUsage::Tr31K3AsymmetricKeyForKeyAgreement => { /* ... */ },
///     KeyUsage::Tr31M1Iso97971MacKey => { /* ... */ },
///     KeyUsage::Tr31M3Iso97973MacKey => { /* ... */ },
///     KeyUsage::Tr31M6Iso97975CmacKey => { /* ... */ },
///     KeyUsage::Tr31M7HmacKey => { /* ... */ },
///     KeyUsage::Tr31P0PinEncryptionKey => { /* ... */ },
///     KeyUsage::Tr31P1PinGenerationKey => { /* ... */ },
///     KeyUsage::Tr31S0AsymmetricKeyForDigitalSignature => { /* ... */ },
///     KeyUsage::Tr31V1Ibm3624PinVerificationKey => { /* ... */ },
///     KeyUsage::Tr31V2VisaPinVerificationKey => { /* ... */ },
///     other @ _ if other.as_str() == "NewFeature" => { /* handles a case for `NewFeature` */ },
///     _ => { /* ... */ },
/// }
/// ```
/// The above code demonstrates that when `keyusage` represents
/// `NewFeature`, the execution path will lead to the second last match arm,
/// even though the enum does not contain a variant `KeyUsage::NewFeature`
/// in the current version of SDK. The reason is that the variable `other`,
/// created by the `@` operator, is bound to
/// `KeyUsage::Unknown(UnknownVariantValue("NewFeature".to_owned()))`
/// and calling `as_str` on it yields `"NewFeature"`.
/// This match expression is forward-compatible when executed with a newer
/// version of SDK where the variant `KeyUsage::NewFeature` is defined.
/// Specifically, when `keyusage` represents `NewFeature`,
/// the execution path will hit the second last match arm as before by virtue of
/// calling `as_str` on `KeyUsage::NewFeature` also yielding `"NewFeature"`.
///
/// Explicitly matching on the `Unknown` variant should
/// be avoided for two reasons:
/// - The inner data `UnknownVariantValue` is opaque, and no further information can be extracted.
/// - It might inadvertently shadow other intended match arms.
///
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(
    ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash,
)]
pub enum KeyUsage {
    #[allow(missing_docs)] // documentation missing in model
    Tr31B0BaseDerivationKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31C0CardVerificationKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31D0SymmetricDataEncryptionKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31D1AsymmetricKeyForDataEncryption,
    #[allow(missing_docs)] // documentation missing in model
    Tr31E0EmvMkeyAppCryptograms,
    #[allow(missing_docs)] // documentation missing in model
    Tr31E1EmvMkeyConfidentiality,
    #[allow(missing_docs)] // documentation missing in model
    Tr31E2EmvMkeyIntegrity,
    #[allow(missing_docs)] // documentation missing in model
    Tr31E4EmvMkeyDynamicNumbers,
    #[allow(missing_docs)] // documentation missing in model
    Tr31E5EmvMkeyCardPersonalization,
    #[allow(missing_docs)] // documentation missing in model
    Tr31E6EmvMkeyOther,
    #[allow(missing_docs)] // documentation missing in model
    Tr31K0KeyEncryptionKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31K1KeyBlockProtectionKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31K2Tr34AsymmetricKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31K3AsymmetricKeyForKeyAgreement,
    #[allow(missing_docs)] // documentation missing in model
    Tr31M1Iso97971MacKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31M3Iso97973MacKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31M6Iso97975CmacKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31M7HmacKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31P0PinEncryptionKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31P1PinGenerationKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31S0AsymmetricKeyForDigitalSignature,
    #[allow(missing_docs)] // documentation missing in model
    Tr31V1Ibm3624PinVerificationKey,
    #[allow(missing_docs)] // documentation missing in model
    Tr31V2VisaPinVerificationKey,
    /// `Unknown` contains new variants that have been added since this code was generated.
    #[deprecated(note = "Don't directly match on `Unknown`. See the docs on this enum for the correct way to handle unknown variants.")]
    Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue),
}
impl ::std::convert::From<&str> for KeyUsage {
    fn from(s: &str) -> Self {
        match s {
            "TR31_B0_BASE_DERIVATION_KEY" => KeyUsage::Tr31B0BaseDerivationKey,
            "TR31_C0_CARD_VERIFICATION_KEY" => KeyUsage::Tr31C0CardVerificationKey,
            "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY" => KeyUsage::Tr31D0SymmetricDataEncryptionKey,
            "TR31_D1_ASYMMETRIC_KEY_FOR_DATA_ENCRYPTION" => KeyUsage::Tr31D1AsymmetricKeyForDataEncryption,
            "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS" => KeyUsage::Tr31E0EmvMkeyAppCryptograms,
            "TR31_E1_EMV_MKEY_CONFIDENTIALITY" => KeyUsage::Tr31E1EmvMkeyConfidentiality,
            "TR31_E2_EMV_MKEY_INTEGRITY" => KeyUsage::Tr31E2EmvMkeyIntegrity,
            "TR31_E4_EMV_MKEY_DYNAMIC_NUMBERS" => KeyUsage::Tr31E4EmvMkeyDynamicNumbers,
            "TR31_E5_EMV_MKEY_CARD_PERSONALIZATION" => KeyUsage::Tr31E5EmvMkeyCardPersonalization,
            "TR31_E6_EMV_MKEY_OTHER" => KeyUsage::Tr31E6EmvMkeyOther,
            "TR31_K0_KEY_ENCRYPTION_KEY" => KeyUsage::Tr31K0KeyEncryptionKey,
            "TR31_K1_KEY_BLOCK_PROTECTION_KEY" => KeyUsage::Tr31K1KeyBlockProtectionKey,
            "TR31_K2_TR34_ASYMMETRIC_KEY" => KeyUsage::Tr31K2Tr34AsymmetricKey,
            "TR31_K3_ASYMMETRIC_KEY_FOR_KEY_AGREEMENT" => KeyUsage::Tr31K3AsymmetricKeyForKeyAgreement,
            "TR31_M1_ISO_9797_1_MAC_KEY" => KeyUsage::Tr31M1Iso97971MacKey,
            "TR31_M3_ISO_9797_3_MAC_KEY" => KeyUsage::Tr31M3Iso97973MacKey,
            "TR31_M6_ISO_9797_5_CMAC_KEY" => KeyUsage::Tr31M6Iso97975CmacKey,
            "TR31_M7_HMAC_KEY" => KeyUsage::Tr31M7HmacKey,
            "TR31_P0_PIN_ENCRYPTION_KEY" => KeyUsage::Tr31P0PinEncryptionKey,
            "TR31_P1_PIN_GENERATION_KEY" => KeyUsage::Tr31P1PinGenerationKey,
            "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE" => KeyUsage::Tr31S0AsymmetricKeyForDigitalSignature,
            "TR31_V1_IBM3624_PIN_VERIFICATION_KEY" => KeyUsage::Tr31V1Ibm3624PinVerificationKey,
            "TR31_V2_VISA_PIN_VERIFICATION_KEY" => KeyUsage::Tr31V2VisaPinVerificationKey,
            other => KeyUsage::Unknown(crate::primitives::sealed_enum_unknown::UnknownVariantValue(other.to_owned())),
        }
    }
}
impl ::std::str::FromStr for KeyUsage {
    type Err = ::std::convert::Infallible;

    fn from_str(s: &str) -> ::std::result::Result<Self, <Self as ::std::str::FromStr>::Err> {
        ::std::result::Result::Ok(KeyUsage::from(s))
    }
}
impl KeyUsage {
    /// Returns the `&str` value of the enum member.
    pub fn as_str(&self) -> &str {
        match self {
            KeyUsage::Tr31B0BaseDerivationKey => "TR31_B0_BASE_DERIVATION_KEY",
            KeyUsage::Tr31C0CardVerificationKey => "TR31_C0_CARD_VERIFICATION_KEY",
            KeyUsage::Tr31D0SymmetricDataEncryptionKey => "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
            KeyUsage::Tr31D1AsymmetricKeyForDataEncryption => "TR31_D1_ASYMMETRIC_KEY_FOR_DATA_ENCRYPTION",
            KeyUsage::Tr31E0EmvMkeyAppCryptograms => "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
            KeyUsage::Tr31E1EmvMkeyConfidentiality => "TR31_E1_EMV_MKEY_CONFIDENTIALITY",
            KeyUsage::Tr31E2EmvMkeyIntegrity => "TR31_E2_EMV_MKEY_INTEGRITY",
            KeyUsage::Tr31E4EmvMkeyDynamicNumbers => "TR31_E4_EMV_MKEY_DYNAMIC_NUMBERS",
            KeyUsage::Tr31E5EmvMkeyCardPersonalization => "TR31_E5_EMV_MKEY_CARD_PERSONALIZATION",
            KeyUsage::Tr31E6EmvMkeyOther => "TR31_E6_EMV_MKEY_OTHER",
            KeyUsage::Tr31K0KeyEncryptionKey => "TR31_K0_KEY_ENCRYPTION_KEY",
            KeyUsage::Tr31K1KeyBlockProtectionKey => "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
            KeyUsage::Tr31K2Tr34AsymmetricKey => "TR31_K2_TR34_ASYMMETRIC_KEY",
            KeyUsage::Tr31K3AsymmetricKeyForKeyAgreement => "TR31_K3_ASYMMETRIC_KEY_FOR_KEY_AGREEMENT",
            KeyUsage::Tr31M1Iso97971MacKey => "TR31_M1_ISO_9797_1_MAC_KEY",
            KeyUsage::Tr31M3Iso97973MacKey => "TR31_M3_ISO_9797_3_MAC_KEY",
            KeyUsage::Tr31M6Iso97975CmacKey => "TR31_M6_ISO_9797_5_CMAC_KEY",
            KeyUsage::Tr31M7HmacKey => "TR31_M7_HMAC_KEY",
            KeyUsage::Tr31P0PinEncryptionKey => "TR31_P0_PIN_ENCRYPTION_KEY",
            KeyUsage::Tr31P1PinGenerationKey => "TR31_P1_PIN_GENERATION_KEY",
            KeyUsage::Tr31S0AsymmetricKeyForDigitalSignature => "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE",
            KeyUsage::Tr31V1Ibm3624PinVerificationKey => "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
            KeyUsage::Tr31V2VisaPinVerificationKey => "TR31_V2_VISA_PIN_VERIFICATION_KEY",
            KeyUsage::Unknown(value) => value.as_str(),
        }
    }
    /// Returns all the `&str` representations of the enum members.
    pub const fn values() -> &'static [&'static str] {
        &[
            "TR31_B0_BASE_DERIVATION_KEY",
            "TR31_C0_CARD_VERIFICATION_KEY",
            "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
            "TR31_D1_ASYMMETRIC_KEY_FOR_DATA_ENCRYPTION",
            "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
            "TR31_E1_EMV_MKEY_CONFIDENTIALITY",
            "TR31_E2_EMV_MKEY_INTEGRITY",
            "TR31_E4_EMV_MKEY_DYNAMIC_NUMBERS",
            "TR31_E5_EMV_MKEY_CARD_PERSONALIZATION",
            "TR31_E6_EMV_MKEY_OTHER",
            "TR31_K0_KEY_ENCRYPTION_KEY",
            "TR31_K1_KEY_BLOCK_PROTECTION_KEY",
            "TR31_K2_TR34_ASYMMETRIC_KEY",
            "TR31_K3_ASYMMETRIC_KEY_FOR_KEY_AGREEMENT",
            "TR31_M1_ISO_9797_1_MAC_KEY",
            "TR31_M3_ISO_9797_3_MAC_KEY",
            "TR31_M6_ISO_9797_5_CMAC_KEY",
            "TR31_M7_HMAC_KEY",
            "TR31_P0_PIN_ENCRYPTION_KEY",
            "TR31_P1_PIN_GENERATION_KEY",
            "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE",
            "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
            "TR31_V2_VISA_PIN_VERIFICATION_KEY",
        ]
    }
}
impl ::std::convert::AsRef<str> for KeyUsage {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl KeyUsage {
    /// Parses the enum value while disallowing unknown variants.
    ///
    /// Unknown variants will result in an error.
    pub fn try_parse(value: &str) -> ::std::result::Result<Self, crate::error::UnknownVariantError> {
        match Self::from(value) {
            #[allow(deprecated)]
            Self::Unknown(_) => ::std::result::Result::Err(crate::error::UnknownVariantError::new(value)),
            known => Ok(known),
        }
    }
}
impl ::std::fmt::Display for KeyUsage {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            KeyUsage::Tr31B0BaseDerivationKey => write!(f, "TR31_B0_BASE_DERIVATION_KEY"),
            KeyUsage::Tr31C0CardVerificationKey => write!(f, "TR31_C0_CARD_VERIFICATION_KEY"),
            KeyUsage::Tr31D0SymmetricDataEncryptionKey => write!(f, "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY"),
            KeyUsage::Tr31D1AsymmetricKeyForDataEncryption => write!(f, "TR31_D1_ASYMMETRIC_KEY_FOR_DATA_ENCRYPTION"),
            KeyUsage::Tr31E0EmvMkeyAppCryptograms => write!(f, "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS"),
            KeyUsage::Tr31E1EmvMkeyConfidentiality => write!(f, "TR31_E1_EMV_MKEY_CONFIDENTIALITY"),
            KeyUsage::Tr31E2EmvMkeyIntegrity => write!(f, "TR31_E2_EMV_MKEY_INTEGRITY"),
            KeyUsage::Tr31E4EmvMkeyDynamicNumbers => write!(f, "TR31_E4_EMV_MKEY_DYNAMIC_NUMBERS"),
            KeyUsage::Tr31E5EmvMkeyCardPersonalization => write!(f, "TR31_E5_EMV_MKEY_CARD_PERSONALIZATION"),
            KeyUsage::Tr31E6EmvMkeyOther => write!(f, "TR31_E6_EMV_MKEY_OTHER"),
            KeyUsage::Tr31K0KeyEncryptionKey => write!(f, "TR31_K0_KEY_ENCRYPTION_KEY"),
            KeyUsage::Tr31K1KeyBlockProtectionKey => write!(f, "TR31_K1_KEY_BLOCK_PROTECTION_KEY"),
            KeyUsage::Tr31K2Tr34AsymmetricKey => write!(f, "TR31_K2_TR34_ASYMMETRIC_KEY"),
            KeyUsage::Tr31K3AsymmetricKeyForKeyAgreement => write!(f, "TR31_K3_ASYMMETRIC_KEY_FOR_KEY_AGREEMENT"),
            KeyUsage::Tr31M1Iso97971MacKey => write!(f, "TR31_M1_ISO_9797_1_MAC_KEY"),
            KeyUsage::Tr31M3Iso97973MacKey => write!(f, "TR31_M3_ISO_9797_3_MAC_KEY"),
            KeyUsage::Tr31M6Iso97975CmacKey => write!(f, "TR31_M6_ISO_9797_5_CMAC_KEY"),
            KeyUsage::Tr31M7HmacKey => write!(f, "TR31_M7_HMAC_KEY"),
            KeyUsage::Tr31P0PinEncryptionKey => write!(f, "TR31_P0_PIN_ENCRYPTION_KEY"),
            KeyUsage::Tr31P1PinGenerationKey => write!(f, "TR31_P1_PIN_GENERATION_KEY"),
            KeyUsage::Tr31S0AsymmetricKeyForDigitalSignature => write!(f, "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE"),
            KeyUsage::Tr31V1Ibm3624PinVerificationKey => write!(f, "TR31_V1_IBM3624_PIN_VERIFICATION_KEY"),
            KeyUsage::Tr31V2VisaPinVerificationKey => write!(f, "TR31_V2_VISA_PIN_VERIFICATION_KEY"),
            KeyUsage::Unknown(value) => write!(f, "{}", value),
        }
    }
}
