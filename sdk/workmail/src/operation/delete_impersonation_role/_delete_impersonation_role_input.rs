// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteImpersonationRoleInput {
    /// <p>The WorkMail organization from which to delete the impersonation role.</p>
    pub organization_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the impersonation role to delete.</p>
    pub impersonation_role_id: ::std::option::Option<::std::string::String>,
}
impl DeleteImpersonationRoleInput {
    /// <p>The WorkMail organization from which to delete the impersonation role.</p>
    pub fn organization_id(&self) -> ::std::option::Option<&str> {
        self.organization_id.as_deref()
    }
    /// <p>The ID of the impersonation role to delete.</p>
    pub fn impersonation_role_id(&self) -> ::std::option::Option<&str> {
        self.impersonation_role_id.as_deref()
    }
}
impl DeleteImpersonationRoleInput {
    /// Creates a new builder-style object to manufacture [`DeleteImpersonationRoleInput`](crate::operation::delete_impersonation_role::DeleteImpersonationRoleInput).
    pub fn builder() -> crate::operation::delete_impersonation_role::builders::DeleteImpersonationRoleInputBuilder {
        crate::operation::delete_impersonation_role::builders::DeleteImpersonationRoleInputBuilder::default()
    }
}

/// A builder for [`DeleteImpersonationRoleInput`](crate::operation::delete_impersonation_role::DeleteImpersonationRoleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteImpersonationRoleInputBuilder {
    pub(crate) organization_id: ::std::option::Option<::std::string::String>,
    pub(crate) impersonation_role_id: ::std::option::Option<::std::string::String>,
}
impl DeleteImpersonationRoleInputBuilder {
    /// <p>The WorkMail organization from which to delete the impersonation role.</p>
    /// This field is required.
    pub fn organization_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The WorkMail organization from which to delete the impersonation role.</p>
    pub fn set_organization_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_id = input;
        self
    }
    /// <p>The WorkMail organization from which to delete the impersonation role.</p>
    pub fn get_organization_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_id
    }
    /// <p>The ID of the impersonation role to delete.</p>
    /// This field is required.
    pub fn impersonation_role_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.impersonation_role_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the impersonation role to delete.</p>
    pub fn set_impersonation_role_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.impersonation_role_id = input;
        self
    }
    /// <p>The ID of the impersonation role to delete.</p>
    pub fn get_impersonation_role_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.impersonation_role_id
    }
    /// Consumes the builder and constructs a [`DeleteImpersonationRoleInput`](crate::operation::delete_impersonation_role::DeleteImpersonationRoleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_impersonation_role::DeleteImpersonationRoleInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_impersonation_role::DeleteImpersonationRoleInput {
            organization_id: self.organization_id,
            impersonation_role_id: self.impersonation_role_id,
        })
    }
}
