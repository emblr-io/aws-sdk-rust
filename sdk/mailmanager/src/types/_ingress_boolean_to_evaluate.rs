// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The union type representing the allowed types of operands for a boolean condition.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum IngressBooleanToEvaluate {
    /// <p>The structure type for a boolean condition stating the Add On ARN and its returned value.</p>
    Analysis(crate::types::IngressAnalysis),
    /// <p>The structure type for a boolean condition that provides the address lists to evaluate incoming traffic on.</p>
    IsInAddressList(crate::types::IngressIsInAddressList),
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
impl IngressBooleanToEvaluate {
    /// Tries to convert the enum instance into [`Analysis`](crate::types::IngressBooleanToEvaluate::Analysis), extracting the inner [`IngressAnalysis`](crate::types::IngressAnalysis).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_analysis(&self) -> ::std::result::Result<&crate::types::IngressAnalysis, &Self> {
        if let IngressBooleanToEvaluate::Analysis(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Analysis`](crate::types::IngressBooleanToEvaluate::Analysis).
    pub fn is_analysis(&self) -> bool {
        self.as_analysis().is_ok()
    }
    /// Tries to convert the enum instance into [`IsInAddressList`](crate::types::IngressBooleanToEvaluate::IsInAddressList), extracting the inner [`IngressIsInAddressList`](crate::types::IngressIsInAddressList).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_is_in_address_list(&self) -> ::std::result::Result<&crate::types::IngressIsInAddressList, &Self> {
        if let IngressBooleanToEvaluate::IsInAddressList(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`IsInAddressList`](crate::types::IngressBooleanToEvaluate::IsInAddressList).
    pub fn is_is_in_address_list(&self) -> bool {
        self.as_is_in_address_list().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
