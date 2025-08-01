// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateDistributionTenantWebAclInput {
    /// <p>The ID of the distribution tenant.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The current version of the distribution tenant that you're disassociating from the WAF web ACL. This is the <code>ETag</code> value returned in the response to the <code>GetDistributionTenant</code> API operation.</p>
    pub if_match: ::std::option::Option<::std::string::String>,
}
impl DisassociateDistributionTenantWebAclInput {
    /// <p>The ID of the distribution tenant.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The current version of the distribution tenant that you're disassociating from the WAF web ACL. This is the <code>ETag</code> value returned in the response to the <code>GetDistributionTenant</code> API operation.</p>
    pub fn if_match(&self) -> ::std::option::Option<&str> {
        self.if_match.as_deref()
    }
}
impl DisassociateDistributionTenantWebAclInput {
    /// Creates a new builder-style object to manufacture [`DisassociateDistributionTenantWebAclInput`](crate::operation::disassociate_distribution_tenant_web_acl::DisassociateDistributionTenantWebAclInput).
    pub fn builder() -> crate::operation::disassociate_distribution_tenant_web_acl::builders::DisassociateDistributionTenantWebAclInputBuilder {
        crate::operation::disassociate_distribution_tenant_web_acl::builders::DisassociateDistributionTenantWebAclInputBuilder::default()
    }
}

/// A builder for [`DisassociateDistributionTenantWebAclInput`](crate::operation::disassociate_distribution_tenant_web_acl::DisassociateDistributionTenantWebAclInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateDistributionTenantWebAclInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) if_match: ::std::option::Option<::std::string::String>,
}
impl DisassociateDistributionTenantWebAclInputBuilder {
    /// <p>The ID of the distribution tenant.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the distribution tenant.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the distribution tenant.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The current version of the distribution tenant that you're disassociating from the WAF web ACL. This is the <code>ETag</code> value returned in the response to the <code>GetDistributionTenant</code> API operation.</p>
    pub fn if_match(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.if_match = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current version of the distribution tenant that you're disassociating from the WAF web ACL. This is the <code>ETag</code> value returned in the response to the <code>GetDistributionTenant</code> API operation.</p>
    pub fn set_if_match(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.if_match = input;
        self
    }
    /// <p>The current version of the distribution tenant that you're disassociating from the WAF web ACL. This is the <code>ETag</code> value returned in the response to the <code>GetDistributionTenant</code> API operation.</p>
    pub fn get_if_match(&self) -> &::std::option::Option<::std::string::String> {
        &self.if_match
    }
    /// Consumes the builder and constructs a [`DisassociateDistributionTenantWebAclInput`](crate::operation::disassociate_distribution_tenant_web_acl::DisassociateDistributionTenantWebAclInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_distribution_tenant_web_acl::DisassociateDistributionTenantWebAclInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::disassociate_distribution_tenant_web_acl::DisassociateDistributionTenantWebAclInput {
                id: self.id,
                if_match: self.if_match,
            },
        )
    }
}
