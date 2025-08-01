// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterIdentityProviderOutput {
    /// <p>Metadata that describes the results of an identity provider operation.</p>
    pub identity_provider_summary: ::std::option::Option<crate::types::IdentityProviderSummary>,
    _request_id: Option<String>,
}
impl RegisterIdentityProviderOutput {
    /// <p>Metadata that describes the results of an identity provider operation.</p>
    pub fn identity_provider_summary(&self) -> ::std::option::Option<&crate::types::IdentityProviderSummary> {
        self.identity_provider_summary.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for RegisterIdentityProviderOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RegisterIdentityProviderOutput {
    /// Creates a new builder-style object to manufacture [`RegisterIdentityProviderOutput`](crate::operation::register_identity_provider::RegisterIdentityProviderOutput).
    pub fn builder() -> crate::operation::register_identity_provider::builders::RegisterIdentityProviderOutputBuilder {
        crate::operation::register_identity_provider::builders::RegisterIdentityProviderOutputBuilder::default()
    }
}

/// A builder for [`RegisterIdentityProviderOutput`](crate::operation::register_identity_provider::RegisterIdentityProviderOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterIdentityProviderOutputBuilder {
    pub(crate) identity_provider_summary: ::std::option::Option<crate::types::IdentityProviderSummary>,
    _request_id: Option<String>,
}
impl RegisterIdentityProviderOutputBuilder {
    /// <p>Metadata that describes the results of an identity provider operation.</p>
    /// This field is required.
    pub fn identity_provider_summary(mut self, input: crate::types::IdentityProviderSummary) -> Self {
        self.identity_provider_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Metadata that describes the results of an identity provider operation.</p>
    pub fn set_identity_provider_summary(mut self, input: ::std::option::Option<crate::types::IdentityProviderSummary>) -> Self {
        self.identity_provider_summary = input;
        self
    }
    /// <p>Metadata that describes the results of an identity provider operation.</p>
    pub fn get_identity_provider_summary(&self) -> &::std::option::Option<crate::types::IdentityProviderSummary> {
        &self.identity_provider_summary
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RegisterIdentityProviderOutput`](crate::operation::register_identity_provider::RegisterIdentityProviderOutput).
    pub fn build(self) -> crate::operation::register_identity_provider::RegisterIdentityProviderOutput {
        crate::operation::register_identity_provider::RegisterIdentityProviderOutput {
            identity_provider_summary: self.identity_provider_summary,
            _request_id: self._request_id,
        }
    }
}
