// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Removes CloudTrail delegated administrator permissions from a specified member account in an organization that is currently designated as a delegated administrator.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeregisterOrganizationDelegatedAdminInput {
    /// <p>A delegated administrator account ID. This is a member account in an organization that is currently designated as a delegated administrator.</p>
    pub delegated_admin_account_id: ::std::option::Option<::std::string::String>,
}
impl DeregisterOrganizationDelegatedAdminInput {
    /// <p>A delegated administrator account ID. This is a member account in an organization that is currently designated as a delegated administrator.</p>
    pub fn delegated_admin_account_id(&self) -> ::std::option::Option<&str> {
        self.delegated_admin_account_id.as_deref()
    }
}
impl DeregisterOrganizationDelegatedAdminInput {
    /// Creates a new builder-style object to manufacture [`DeregisterOrganizationDelegatedAdminInput`](crate::operation::deregister_organization_delegated_admin::DeregisterOrganizationDelegatedAdminInput).
    pub fn builder() -> crate::operation::deregister_organization_delegated_admin::builders::DeregisterOrganizationDelegatedAdminInputBuilder {
        crate::operation::deregister_organization_delegated_admin::builders::DeregisterOrganizationDelegatedAdminInputBuilder::default()
    }
}

/// A builder for [`DeregisterOrganizationDelegatedAdminInput`](crate::operation::deregister_organization_delegated_admin::DeregisterOrganizationDelegatedAdminInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeregisterOrganizationDelegatedAdminInputBuilder {
    pub(crate) delegated_admin_account_id: ::std::option::Option<::std::string::String>,
}
impl DeregisterOrganizationDelegatedAdminInputBuilder {
    /// <p>A delegated administrator account ID. This is a member account in an organization that is currently designated as a delegated administrator.</p>
    /// This field is required.
    pub fn delegated_admin_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delegated_admin_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A delegated administrator account ID. This is a member account in an organization that is currently designated as a delegated administrator.</p>
    pub fn set_delegated_admin_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delegated_admin_account_id = input;
        self
    }
    /// <p>A delegated administrator account ID. This is a member account in an organization that is currently designated as a delegated administrator.</p>
    pub fn get_delegated_admin_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.delegated_admin_account_id
    }
    /// Consumes the builder and constructs a [`DeregisterOrganizationDelegatedAdminInput`](crate::operation::deregister_organization_delegated_admin::DeregisterOrganizationDelegatedAdminInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::deregister_organization_delegated_admin::DeregisterOrganizationDelegatedAdminInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::deregister_organization_delegated_admin::DeregisterOrganizationDelegatedAdminInput {
                delegated_admin_account_id: self.delegated_admin_account_id,
            },
        )
    }
}
