// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyLunaClientInput {
    /// <p>The ARN of the client.</p>
    pub client_arn: ::std::option::Option<::std::string::String>,
    /// <p>The new certificate for the client.</p>
    pub certificate: ::std::option::Option<::std::string::String>,
}
impl ModifyLunaClientInput {
    /// <p>The ARN of the client.</p>
    pub fn client_arn(&self) -> ::std::option::Option<&str> {
        self.client_arn.as_deref()
    }
    /// <p>The new certificate for the client.</p>
    pub fn certificate(&self) -> ::std::option::Option<&str> {
        self.certificate.as_deref()
    }
}
impl ModifyLunaClientInput {
    /// Creates a new builder-style object to manufacture [`ModifyLunaClientInput`](crate::operation::modify_luna_client::ModifyLunaClientInput).
    pub fn builder() -> crate::operation::modify_luna_client::builders::ModifyLunaClientInputBuilder {
        crate::operation::modify_luna_client::builders::ModifyLunaClientInputBuilder::default()
    }
}

/// A builder for [`ModifyLunaClientInput`](crate::operation::modify_luna_client::ModifyLunaClientInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyLunaClientInputBuilder {
    pub(crate) client_arn: ::std::option::Option<::std::string::String>,
    pub(crate) certificate: ::std::option::Option<::std::string::String>,
}
impl ModifyLunaClientInputBuilder {
    /// <p>The ARN of the client.</p>
    /// This field is required.
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
    /// <p>The new certificate for the client.</p>
    /// This field is required.
    pub fn certificate(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new certificate for the client.</p>
    pub fn set_certificate(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate = input;
        self
    }
    /// <p>The new certificate for the client.</p>
    pub fn get_certificate(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate
    }
    /// Consumes the builder and constructs a [`ModifyLunaClientInput`](crate::operation::modify_luna_client::ModifyLunaClientInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::modify_luna_client::ModifyLunaClientInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::modify_luna_client::ModifyLunaClientInput {
            client_arn: self.client_arn,
            certificate: self.certificate,
        })
    }
}
