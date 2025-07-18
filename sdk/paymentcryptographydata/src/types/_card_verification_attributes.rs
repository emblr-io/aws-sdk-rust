// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Card data parameters that are requried to verify Card Verification Values (CVV/CVV2), Dynamic Card Verification Values (dCVV/dCVV2), or Card Security Codes (CSC).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum CardVerificationAttributes {
    /// <p>Card data parameters that are required to generate a Card Security Code (CSC2) for an AMEX payment card.</p>
    AmexCardSecurityCodeVersion1(crate::types::AmexCardSecurityCodeVersion1),
    /// <p>Card data parameters that are required to verify a Card Security Code (CSC2) for an AMEX payment card.</p>
    AmexCardSecurityCodeVersion2(crate::types::AmexCardSecurityCodeVersion2),
    /// <p>Card data parameters that are required to verify a cardholder verification value for the payment card.</p>
    CardHolderVerificationValue(crate::types::CardHolderVerificationValue),
    /// <p>Card data parameters that are required to verify Card Verification Value (CVV) for the payment card.</p>
    CardVerificationValue1(crate::types::CardVerificationValue1),
    /// <p>Card data parameters that are required to verify Card Verification Value (CVV2) for the payment card.</p>
    CardVerificationValue2(crate::types::CardVerificationValue2),
    /// <p>Card data parameters that are required to verify CDynamic Card Verification Code (dCVC) for the payment card.</p>
    DiscoverDynamicCardVerificationCode(crate::types::DiscoverDynamicCardVerificationCode),
    /// <p>Card data parameters that are required to verify CDynamic Card Verification Code (dCVC) for the payment card.</p>
    DynamicCardVerificationCode(crate::types::DynamicCardVerificationCode),
    /// <p>Card data parameters that are required to verify CDynamic Card Verification Value (dCVV) for the payment card.</p>
    DynamicCardVerificationValue(crate::types::DynamicCardVerificationValue),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl CardVerificationAttributes {
    /// Tries to convert the enum instance into [`AmexCardSecurityCodeVersion1`](crate::types::CardVerificationAttributes::AmexCardSecurityCodeVersion1), extracting the inner [`AmexCardSecurityCodeVersion1`](crate::types::AmexCardSecurityCodeVersion1).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_amex_card_security_code_version1(&self) -> ::std::result::Result<&crate::types::AmexCardSecurityCodeVersion1, &Self> {
        if let CardVerificationAttributes::AmexCardSecurityCodeVersion1(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`AmexCardSecurityCodeVersion1`](crate::types::CardVerificationAttributes::AmexCardSecurityCodeVersion1).
    pub fn is_amex_card_security_code_version1(&self) -> bool {
        self.as_amex_card_security_code_version1().is_ok()
    }
    /// Tries to convert the enum instance into [`AmexCardSecurityCodeVersion2`](crate::types::CardVerificationAttributes::AmexCardSecurityCodeVersion2), extracting the inner [`AmexCardSecurityCodeVersion2`](crate::types::AmexCardSecurityCodeVersion2).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_amex_card_security_code_version2(&self) -> ::std::result::Result<&crate::types::AmexCardSecurityCodeVersion2, &Self> {
        if let CardVerificationAttributes::AmexCardSecurityCodeVersion2(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`AmexCardSecurityCodeVersion2`](crate::types::CardVerificationAttributes::AmexCardSecurityCodeVersion2).
    pub fn is_amex_card_security_code_version2(&self) -> bool {
        self.as_amex_card_security_code_version2().is_ok()
    }
    /// Tries to convert the enum instance into [`CardHolderVerificationValue`](crate::types::CardVerificationAttributes::CardHolderVerificationValue), extracting the inner [`CardHolderVerificationValue`](crate::types::CardHolderVerificationValue).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_card_holder_verification_value(&self) -> ::std::result::Result<&crate::types::CardHolderVerificationValue, &Self> {
        if let CardVerificationAttributes::CardHolderVerificationValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CardHolderVerificationValue`](crate::types::CardVerificationAttributes::CardHolderVerificationValue).
    pub fn is_card_holder_verification_value(&self) -> bool {
        self.as_card_holder_verification_value().is_ok()
    }
    /// Tries to convert the enum instance into [`CardVerificationValue1`](crate::types::CardVerificationAttributes::CardVerificationValue1), extracting the inner [`CardVerificationValue1`](crate::types::CardVerificationValue1).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_card_verification_value1(&self) -> ::std::result::Result<&crate::types::CardVerificationValue1, &Self> {
        if let CardVerificationAttributes::CardVerificationValue1(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CardVerificationValue1`](crate::types::CardVerificationAttributes::CardVerificationValue1).
    pub fn is_card_verification_value1(&self) -> bool {
        self.as_card_verification_value1().is_ok()
    }
    /// Tries to convert the enum instance into [`CardVerificationValue2`](crate::types::CardVerificationAttributes::CardVerificationValue2), extracting the inner [`CardVerificationValue2`](crate::types::CardVerificationValue2).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_card_verification_value2(&self) -> ::std::result::Result<&crate::types::CardVerificationValue2, &Self> {
        if let CardVerificationAttributes::CardVerificationValue2(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CardVerificationValue2`](crate::types::CardVerificationAttributes::CardVerificationValue2).
    pub fn is_card_verification_value2(&self) -> bool {
        self.as_card_verification_value2().is_ok()
    }
    /// Tries to convert the enum instance into [`DiscoverDynamicCardVerificationCode`](crate::types::CardVerificationAttributes::DiscoverDynamicCardVerificationCode), extracting the inner [`DiscoverDynamicCardVerificationCode`](crate::types::DiscoverDynamicCardVerificationCode).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_discover_dynamic_card_verification_code(&self) -> ::std::result::Result<&crate::types::DiscoverDynamicCardVerificationCode, &Self> {
        if let CardVerificationAttributes::DiscoverDynamicCardVerificationCode(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DiscoverDynamicCardVerificationCode`](crate::types::CardVerificationAttributes::DiscoverDynamicCardVerificationCode).
    pub fn is_discover_dynamic_card_verification_code(&self) -> bool {
        self.as_discover_dynamic_card_verification_code().is_ok()
    }
    /// Tries to convert the enum instance into [`DynamicCardVerificationCode`](crate::types::CardVerificationAttributes::DynamicCardVerificationCode), extracting the inner [`DynamicCardVerificationCode`](crate::types::DynamicCardVerificationCode).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_dynamic_card_verification_code(&self) -> ::std::result::Result<&crate::types::DynamicCardVerificationCode, &Self> {
        if let CardVerificationAttributes::DynamicCardVerificationCode(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DynamicCardVerificationCode`](crate::types::CardVerificationAttributes::DynamicCardVerificationCode).
    pub fn is_dynamic_card_verification_code(&self) -> bool {
        self.as_dynamic_card_verification_code().is_ok()
    }
    /// Tries to convert the enum instance into [`DynamicCardVerificationValue`](crate::types::CardVerificationAttributes::DynamicCardVerificationValue), extracting the inner [`DynamicCardVerificationValue`](crate::types::DynamicCardVerificationValue).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_dynamic_card_verification_value(&self) -> ::std::result::Result<&crate::types::DynamicCardVerificationValue, &Self> {
        if let CardVerificationAttributes::DynamicCardVerificationValue(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`DynamicCardVerificationValue`](crate::types::CardVerificationAttributes::DynamicCardVerificationValue).
    pub fn is_dynamic_card_verification_value(&self) -> bool {
        self.as_dynamic_card_verification_value().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
