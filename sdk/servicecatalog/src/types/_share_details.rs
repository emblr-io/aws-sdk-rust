// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the portfolio share operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ShareDetails {
    /// <p>List of accounts for whom the operation succeeded.</p>
    pub successful_shares: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>List of errors.</p>
    pub share_errors: ::std::option::Option<::std::vec::Vec<crate::types::ShareError>>,
}
impl ShareDetails {
    /// <p>List of accounts for whom the operation succeeded.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.successful_shares.is_none()`.
    pub fn successful_shares(&self) -> &[::std::string::String] {
        self.successful_shares.as_deref().unwrap_or_default()
    }
    /// <p>List of errors.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.share_errors.is_none()`.
    pub fn share_errors(&self) -> &[crate::types::ShareError] {
        self.share_errors.as_deref().unwrap_or_default()
    }
}
impl ShareDetails {
    /// Creates a new builder-style object to manufacture [`ShareDetails`](crate::types::ShareDetails).
    pub fn builder() -> crate::types::builders::ShareDetailsBuilder {
        crate::types::builders::ShareDetailsBuilder::default()
    }
}

/// A builder for [`ShareDetails`](crate::types::ShareDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ShareDetailsBuilder {
    pub(crate) successful_shares: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) share_errors: ::std::option::Option<::std::vec::Vec<crate::types::ShareError>>,
}
impl ShareDetailsBuilder {
    /// Appends an item to `successful_shares`.
    ///
    /// To override the contents of this collection use [`set_successful_shares`](Self::set_successful_shares).
    ///
    /// <p>List of accounts for whom the operation succeeded.</p>
    pub fn successful_shares(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.successful_shares.unwrap_or_default();
        v.push(input.into());
        self.successful_shares = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of accounts for whom the operation succeeded.</p>
    pub fn set_successful_shares(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.successful_shares = input;
        self
    }
    /// <p>List of accounts for whom the operation succeeded.</p>
    pub fn get_successful_shares(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.successful_shares
    }
    /// Appends an item to `share_errors`.
    ///
    /// To override the contents of this collection use [`set_share_errors`](Self::set_share_errors).
    ///
    /// <p>List of errors.</p>
    pub fn share_errors(mut self, input: crate::types::ShareError) -> Self {
        let mut v = self.share_errors.unwrap_or_default();
        v.push(input);
        self.share_errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of errors.</p>
    pub fn set_share_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ShareError>>) -> Self {
        self.share_errors = input;
        self
    }
    /// <p>List of errors.</p>
    pub fn get_share_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ShareError>> {
        &self.share_errors
    }
    /// Consumes the builder and constructs a [`ShareDetails`](crate::types::ShareDetails).
    pub fn build(self) -> crate::types::ShareDetails {
        crate::types::ShareDetails {
            successful_shares: self.successful_shares,
            share_errors: self.share_errors,
        }
    }
}
