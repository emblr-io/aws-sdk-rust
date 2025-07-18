// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDistributionTenantByDomainInput {
    /// <p>A domain name associated with the target distribution tenant.</p>
    pub domain: ::std::option::Option<::std::string::String>,
}
impl GetDistributionTenantByDomainInput {
    /// <p>A domain name associated with the target distribution tenant.</p>
    pub fn domain(&self) -> ::std::option::Option<&str> {
        self.domain.as_deref()
    }
}
impl GetDistributionTenantByDomainInput {
    /// Creates a new builder-style object to manufacture [`GetDistributionTenantByDomainInput`](crate::operation::get_distribution_tenant_by_domain::GetDistributionTenantByDomainInput).
    pub fn builder() -> crate::operation::get_distribution_tenant_by_domain::builders::GetDistributionTenantByDomainInputBuilder {
        crate::operation::get_distribution_tenant_by_domain::builders::GetDistributionTenantByDomainInputBuilder::default()
    }
}

/// A builder for [`GetDistributionTenantByDomainInput`](crate::operation::get_distribution_tenant_by_domain::GetDistributionTenantByDomainInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDistributionTenantByDomainInputBuilder {
    pub(crate) domain: ::std::option::Option<::std::string::String>,
}
impl GetDistributionTenantByDomainInputBuilder {
    /// <p>A domain name associated with the target distribution tenant.</p>
    /// This field is required.
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A domain name associated with the target distribution tenant.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>A domain name associated with the target distribution tenant.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// Consumes the builder and constructs a [`GetDistributionTenantByDomainInput`](crate::operation::get_distribution_tenant_by_domain::GetDistributionTenantByDomainInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_distribution_tenant_by_domain::GetDistributionTenantByDomainInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_distribution_tenant_by_domain::GetDistributionTenantByDomainInput { domain: self.domain })
    }
}
