// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImportSourceCredentialsOutput {
    /// <p>The Amazon Resource Name (ARN) of the token.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ImportSourceCredentialsOutput {
    /// <p>The Amazon Resource Name (ARN) of the token.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ImportSourceCredentialsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ImportSourceCredentialsOutput {
    /// Creates a new builder-style object to manufacture [`ImportSourceCredentialsOutput`](crate::operation::import_source_credentials::ImportSourceCredentialsOutput).
    pub fn builder() -> crate::operation::import_source_credentials::builders::ImportSourceCredentialsOutputBuilder {
        crate::operation::import_source_credentials::builders::ImportSourceCredentialsOutputBuilder::default()
    }
}

/// A builder for [`ImportSourceCredentialsOutput`](crate::operation::import_source_credentials::ImportSourceCredentialsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImportSourceCredentialsOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ImportSourceCredentialsOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the token.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the token.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the token.</p>
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
    /// Consumes the builder and constructs a [`ImportSourceCredentialsOutput`](crate::operation::import_source_credentials::ImportSourceCredentialsOutput).
    pub fn build(self) -> crate::operation::import_source_credentials::ImportSourceCredentialsOutput {
        crate::operation::import_source_credentials::ImportSourceCredentialsOutput {
            arn: self.arn,
            _request_id: self._request_id,
        }
    }
}
