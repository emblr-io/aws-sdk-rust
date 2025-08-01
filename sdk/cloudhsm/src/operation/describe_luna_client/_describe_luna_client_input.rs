// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLunaClientInput {
    /// <p>The ARN of the client.</p>
    pub client_arn: ::std::option::Option<::std::string::String>,
    /// <p>The certificate fingerprint.</p>
    pub certificate_fingerprint: ::std::option::Option<::std::string::String>,
}
impl DescribeLunaClientInput {
    /// <p>The ARN of the client.</p>
    pub fn client_arn(&self) -> ::std::option::Option<&str> {
        self.client_arn.as_deref()
    }
    /// <p>The certificate fingerprint.</p>
    pub fn certificate_fingerprint(&self) -> ::std::option::Option<&str> {
        self.certificate_fingerprint.as_deref()
    }
}
impl DescribeLunaClientInput {
    /// Creates a new builder-style object to manufacture [`DescribeLunaClientInput`](crate::operation::describe_luna_client::DescribeLunaClientInput).
    pub fn builder() -> crate::operation::describe_luna_client::builders::DescribeLunaClientInputBuilder {
        crate::operation::describe_luna_client::builders::DescribeLunaClientInputBuilder::default()
    }
}

/// A builder for [`DescribeLunaClientInput`](crate::operation::describe_luna_client::DescribeLunaClientInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLunaClientInputBuilder {
    pub(crate) client_arn: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_fingerprint: ::std::option::Option<::std::string::String>,
}
impl DescribeLunaClientInputBuilder {
    /// <p>The ARN of the client.</p>
    pub fn client_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the client.</p>
    pub fn set_client_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_arn = input;
        self
    }
    /// <p>The ARN of the client.</p>
    pub fn get_client_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_arn
    }
    /// <p>The certificate fingerprint.</p>
    pub fn certificate_fingerprint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_fingerprint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The certificate fingerprint.</p>
    pub fn set_certificate_fingerprint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_fingerprint = input;
        self
    }
    /// <p>The certificate fingerprint.</p>
    pub fn get_certificate_fingerprint(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_fingerprint
    }
    /// Consumes the builder and constructs a [`DescribeLunaClientInput`](crate::operation::describe_luna_client::DescribeLunaClientInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_luna_client::DescribeLunaClientInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_luna_client::DescribeLunaClientInput {
            client_arn: self.client_arn,
            certificate_fingerprint: self.certificate_fingerprint,
        })
    }
}
