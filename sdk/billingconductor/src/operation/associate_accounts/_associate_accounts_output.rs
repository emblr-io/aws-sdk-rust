// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateAccountsOutput {
    /// <p>The Amazon Resource Name (ARN) of the billing group that associates the array of account IDs.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl AssociateAccountsOutput {
    /// <p>The Amazon Resource Name (ARN) of the billing group that associates the array of account IDs.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for AssociateAccountsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateAccountsOutput {
    /// Creates a new builder-style object to manufacture [`AssociateAccountsOutput`](crate::operation::associate_accounts::AssociateAccountsOutput).
    pub fn builder() -> crate::operation::associate_accounts::builders::AssociateAccountsOutputBuilder {
        crate::operation::associate_accounts::builders::AssociateAccountsOutputBuilder::default()
    }
}

/// A builder for [`AssociateAccountsOutput`](crate::operation::associate_accounts::AssociateAccountsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateAccountsOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl AssociateAccountsOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the billing group that associates the array of account IDs.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the billing group that associates the array of account IDs.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the billing group that associates the array of account IDs.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateAccountsOutput`](crate::operation::associate_accounts::AssociateAccountsOutput).
    pub fn build(self) -> crate::operation::associate_accounts::AssociateAccountsOutput {
        crate::operation::associate_accounts::AssociateAccountsOutput {
            arn: self.arn,
            _request_id: self._request_id,
        }
    }
}
