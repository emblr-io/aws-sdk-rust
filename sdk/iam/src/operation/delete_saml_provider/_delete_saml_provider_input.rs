// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteSamlProviderInput {
    /// <p>The Amazon Resource Name (ARN) of the SAML provider to delete.</p>
    pub saml_provider_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteSamlProviderInput {
    /// <p>The Amazon Resource Name (ARN) of the SAML provider to delete.</p>
    pub fn saml_provider_arn(&self) -> ::std::option::Option<&str> {
        self.saml_provider_arn.as_deref()
    }
}
impl DeleteSamlProviderInput {
    /// Creates a new builder-style object to manufacture [`DeleteSamlProviderInput`](crate::operation::delete_saml_provider::DeleteSamlProviderInput).
    pub fn builder() -> crate::operation::delete_saml_provider::builders::DeleteSamlProviderInputBuilder {
        crate::operation::delete_saml_provider::builders::DeleteSamlProviderInputBuilder::default()
    }
}

/// A builder for [`DeleteSamlProviderInput`](crate::operation::delete_saml_provider::DeleteSamlProviderInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteSamlProviderInputBuilder {
    pub(crate) saml_provider_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteSamlProviderInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the SAML provider to delete.</p>
    /// This field is required.
    pub fn saml_provider_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.saml_provider_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the SAML provider to delete.</p>
    pub fn set_saml_provider_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.saml_provider_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the SAML provider to delete.</p>
    pub fn get_saml_provider_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.saml_provider_arn
    }
    /// Consumes the builder and constructs a [`DeleteSamlProviderInput`](crate::operation::delete_saml_provider::DeleteSamlProviderInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_saml_provider::DeleteSamlProviderInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_saml_provider::DeleteSamlProviderInput {
            saml_provider_arn: self.saml_provider_arn,
        })
    }
}
