// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DomainDetails {
    /// <p>The domain information for the Amazon Web Services API call.</p>
    pub domain: ::std::option::Option<::std::string::String>,
}
impl DomainDetails {
    /// <p>The domain information for the Amazon Web Services API call.</p>
    pub fn domain(&self) -> ::std::option::Option<&str> {
        self.domain.as_deref()
    }
}
impl DomainDetails {
    /// Creates a new builder-style object to manufacture [`DomainDetails`](crate::types::DomainDetails).
    pub fn builder() -> crate::types::builders::DomainDetailsBuilder {
        crate::types::builders::DomainDetailsBuilder::default()
    }
}

/// A builder for [`DomainDetails`](crate::types::DomainDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DomainDetailsBuilder {
    pub(crate) domain: ::std::option::Option<::std::string::String>,
}
impl DomainDetailsBuilder {
    /// <p>The domain information for the Amazon Web Services API call.</p>
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain information for the Amazon Web Services API call.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>The domain information for the Amazon Web Services API call.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// Consumes the builder and constructs a [`DomainDetails`](crate::types::DomainDetails).
    pub fn build(self) -> crate::types::DomainDetails {
        crate::types::DomainDetails { domain: self.domain }
    }
}
