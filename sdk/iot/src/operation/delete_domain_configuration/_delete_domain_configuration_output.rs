// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDomainConfigurationOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteDomainConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteDomainConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DeleteDomainConfigurationOutput`](crate::operation::delete_domain_configuration::DeleteDomainConfigurationOutput).
    pub fn builder() -> crate::operation::delete_domain_configuration::builders::DeleteDomainConfigurationOutputBuilder {
        crate::operation::delete_domain_configuration::builders::DeleteDomainConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DeleteDomainConfigurationOutput`](crate::operation::delete_domain_configuration::DeleteDomainConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteDomainConfigurationOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteDomainConfigurationOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteDomainConfigurationOutput`](crate::operation::delete_domain_configuration::DeleteDomainConfigurationOutput).
    pub fn build(self) -> crate::operation::delete_domain_configuration::DeleteDomainConfigurationOutput {
        crate::operation::delete_domain_configuration::DeleteDomainConfigurationOutput {
            _request_id: self._request_id,
        }
    }
}
