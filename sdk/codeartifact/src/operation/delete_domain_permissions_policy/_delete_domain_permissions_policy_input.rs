// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDomainPermissionsPolicyInput {
    /// <p>The name of the domain associated with the resource policy to be deleted.</p>
    pub domain: ::std::option::Option<::std::string::String>,
    /// <p>The 12-digit account number of the Amazon Web Services account that owns the domain. It does not include dashes or spaces.</p>
    pub domain_owner: ::std::option::Option<::std::string::String>,
    /// <p>The current revision of the resource policy to be deleted. This revision is used for optimistic locking, which prevents others from overwriting your changes to the domain's resource policy.</p>
    pub policy_revision: ::std::option::Option<::std::string::String>,
}
impl DeleteDomainPermissionsPolicyInput {
    /// <p>The name of the domain associated with the resource policy to be deleted.</p>
    pub fn domain(&self) -> ::std::option::Option<&str> {
        self.domain.as_deref()
    }
    /// <p>The 12-digit account number of the Amazon Web Services account that owns the domain. It does not include dashes or spaces.</p>
    pub fn domain_owner(&self) -> ::std::option::Option<&str> {
        self.domain_owner.as_deref()
    }
    /// <p>The current revision of the resource policy to be deleted. This revision is used for optimistic locking, which prevents others from overwriting your changes to the domain's resource policy.</p>
    pub fn policy_revision(&self) -> ::std::option::Option<&str> {
        self.policy_revision.as_deref()
    }
}
impl DeleteDomainPermissionsPolicyInput {
    /// Creates a new builder-style object to manufacture [`DeleteDomainPermissionsPolicyInput`](crate::operation::delete_domain_permissions_policy::DeleteDomainPermissionsPolicyInput).
    pub fn builder() -> crate::operation::delete_domain_permissions_policy::builders::DeleteDomainPermissionsPolicyInputBuilder {
        crate::operation::delete_domain_permissions_policy::builders::DeleteDomainPermissionsPolicyInputBuilder::default()
    }
}

/// A builder for [`DeleteDomainPermissionsPolicyInput`](crate::operation::delete_domain_permissions_policy::DeleteDomainPermissionsPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteDomainPermissionsPolicyInputBuilder {
    pub(crate) domain: ::std::option::Option<::std::string::String>,
    pub(crate) domain_owner: ::std::option::Option<::std::string::String>,
    pub(crate) policy_revision: ::std::option::Option<::std::string::String>,
}
impl DeleteDomainPermissionsPolicyInputBuilder {
    /// <p>The name of the domain associated with the resource policy to be deleted.</p>
    /// This field is required.
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the domain associated with the resource policy to be deleted.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>The name of the domain associated with the resource policy to be deleted.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// <p>The 12-digit account number of the Amazon Web Services account that owns the domain. It does not include dashes or spaces.</p>
    pub fn domain_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The 12-digit account number of the Amazon Web Services account that owns the domain. It does not include dashes or spaces.</p>
    pub fn set_domain_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_owner = input;
        self
    }
    /// <p>The 12-digit account number of the Amazon Web Services account that owns the domain. It does not include dashes or spaces.</p>
    pub fn get_domain_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_owner
    }
    /// <p>The current revision of the resource policy to be deleted. This revision is used for optimistic locking, which prevents others from overwriting your changes to the domain's resource policy.</p>
    pub fn policy_revision(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_revision = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current revision of the resource policy to be deleted. This revision is used for optimistic locking, which prevents others from overwriting your changes to the domain's resource policy.</p>
    pub fn set_policy_revision(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_revision = input;
        self
    }
    /// <p>The current revision of the resource policy to be deleted. This revision is used for optimistic locking, which prevents others from overwriting your changes to the domain's resource policy.</p>
    pub fn get_policy_revision(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_revision
    }
    /// Consumes the builder and constructs a [`DeleteDomainPermissionsPolicyInput`](crate::operation::delete_domain_permissions_policy::DeleteDomainPermissionsPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_domain_permissions_policy::DeleteDomainPermissionsPolicyInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_domain_permissions_policy::DeleteDomainPermissionsPolicyInput {
            domain: self.domain,
            domain_owner: self.domain_owner,
            policy_revision: self.policy_revision,
        })
    }
}
