// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDomainNameOutput {
    /// <p>The configuration for the <code>DomainName</code>.</p>
    pub domain_name_config: ::std::option::Option<crate::types::DomainNameConfig>,
    _request_id: Option<String>,
}
impl CreateDomainNameOutput {
    /// <p>The configuration for the <code>DomainName</code>.</p>
    pub fn domain_name_config(&self) -> ::std::option::Option<&crate::types::DomainNameConfig> {
        self.domain_name_config.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateDomainNameOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateDomainNameOutput {
    /// Creates a new builder-style object to manufacture [`CreateDomainNameOutput`](crate::operation::create_domain_name::CreateDomainNameOutput).
    pub fn builder() -> crate::operation::create_domain_name::builders::CreateDomainNameOutputBuilder {
        crate::operation::create_domain_name::builders::CreateDomainNameOutputBuilder::default()
    }
}

/// A builder for [`CreateDomainNameOutput`](crate::operation::create_domain_name::CreateDomainNameOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDomainNameOutputBuilder {
    pub(crate) domain_name_config: ::std::option::Option<crate::types::DomainNameConfig>,
    _request_id: Option<String>,
}
impl CreateDomainNameOutputBuilder {
    /// <p>The configuration for the <code>DomainName</code>.</p>
    pub fn domain_name_config(mut self, input: crate::types::DomainNameConfig) -> Self {
        self.domain_name_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for the <code>DomainName</code>.</p>
    pub fn set_domain_name_config(mut self, input: ::std::option::Option<crate::types::DomainNameConfig>) -> Self {
        self.domain_name_config = input;
        self
    }
    /// <p>The configuration for the <code>DomainName</code>.</p>
    pub fn get_domain_name_config(&self) -> &::std::option::Option<crate::types::DomainNameConfig> {
        &self.domain_name_config
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateDomainNameOutput`](crate::operation::create_domain_name::CreateDomainNameOutput).
    pub fn build(self) -> crate::operation::create_domain_name::CreateDomainNameOutput {
        crate::operation::create_domain_name::CreateDomainNameOutput {
            domain_name_config: self.domain_name_config,
            _request_id: self._request_id,
        }
    }
}
