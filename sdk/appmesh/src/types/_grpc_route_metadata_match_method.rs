// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents the match method. Specify one of the match values.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum GrpcRouteMetadataMatchMethod {
    /// <p>The value sent by the client must match the specified value exactly.</p>
    Exact(::std::string::String),
    /// <p>The value sent by the client must begin with the specified characters.</p>
    Prefix(::std::string::String),
    /// <p>An object that represents the range of values to match on.</p>
    Range(crate::types::MatchRange),
    /// <p>The value sent by the client must include the specified characters.</p>
    Regex(::std::string::String),
    /// <p>The value sent by the client must end with the specified characters.</p>
    Suffix(::std::string::String),
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
impl GrpcRouteMetadataMatchMethod {
    /// Tries to convert the enum instance into [`Exact`](crate::types::GrpcRouteMetadataMatchMethod::Exact), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_exact(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let GrpcRouteMetadataMatchMethod::Exact(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Exact`](crate::types::GrpcRouteMetadataMatchMethod::Exact).
    pub fn is_exact(&self) -> bool {
        self.as_exact().is_ok()
    }
    /// Tries to convert the enum instance into [`Prefix`](crate::types::GrpcRouteMetadataMatchMethod::Prefix), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_prefix(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let GrpcRouteMetadataMatchMethod::Prefix(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Prefix`](crate::types::GrpcRouteMetadataMatchMethod::Prefix).
    pub fn is_prefix(&self) -> bool {
        self.as_prefix().is_ok()
    }
    /// Tries to convert the enum instance into [`Range`](crate::types::GrpcRouteMetadataMatchMethod::Range), extracting the inner [`MatchRange`](crate::types::MatchRange).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_range(&self) -> ::std::result::Result<&crate::types::MatchRange, &Self> {
        if let GrpcRouteMetadataMatchMethod::Range(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Range`](crate::types::GrpcRouteMetadataMatchMethod::Range).
    pub fn is_range(&self) -> bool {
        self.as_range().is_ok()
    }
    /// Tries to convert the enum instance into [`Regex`](crate::types::GrpcRouteMetadataMatchMethod::Regex), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_regex(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let GrpcRouteMetadataMatchMethod::Regex(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Regex`](crate::types::GrpcRouteMetadataMatchMethod::Regex).
    pub fn is_regex(&self) -> bool {
        self.as_regex().is_ok()
    }
    /// Tries to convert the enum instance into [`Suffix`](crate::types::GrpcRouteMetadataMatchMethod::Suffix), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_suffix(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let GrpcRouteMetadataMatchMethod::Suffix(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Suffix`](crate::types::GrpcRouteMetadataMatchMethod::Suffix).
    pub fn is_suffix(&self) -> bool {
        self.as_suffix().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
