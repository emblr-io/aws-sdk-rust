// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration information of the external data source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum Configuration {
    /// <p>The configuration information of the Amazon Connect data source.</p>
    ConnectConfiguration(crate::types::ConnectConfiguration),
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
impl Configuration {
    #[allow(irrefutable_let_patterns)]
    /// Tries to convert the enum instance into [`ConnectConfiguration`](crate::types::Configuration::ConnectConfiguration), extracting the inner [`ConnectConfiguration`](crate::types::ConnectConfiguration).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_connect_configuration(&self) -> ::std::result::Result<&crate::types::ConnectConfiguration, &Self> {
        if let Configuration::ConnectConfiguration(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ConnectConfiguration`](crate::types::Configuration::ConnectConfiguration).
    pub fn is_connect_configuration(&self) -> bool {
        self.as_connect_configuration().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
