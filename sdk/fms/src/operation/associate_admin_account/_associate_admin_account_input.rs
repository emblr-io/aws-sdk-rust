// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateAdminAccountInput {
    /// <p>The Amazon Web Services account ID to associate with Firewall Manager as the Firewall Manager default administrator account. This account must be a member account of the organization in Organizations whose resources you want to protect. For more information about Organizations, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts.html">Managing the Amazon Web Services Accounts in Your Organization</a>.</p>
    pub admin_account: ::std::option::Option<::std::string::String>,
}
impl AssociateAdminAccountInput {
    /// <p>The Amazon Web Services account ID to associate with Firewall Manager as the Firewall Manager default administrator account. This account must be a member account of the organization in Organizations whose resources you want to protect. For more information about Organizations, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts.html">Managing the Amazon Web Services Accounts in Your Organization</a>.</p>
    pub fn admin_account(&self) -> ::std::option::Option<&str> {
        self.admin_account.as_deref()
    }
}
impl AssociateAdminAccountInput {
    /// Creates a new builder-style object to manufacture [`AssociateAdminAccountInput`](crate::operation::associate_admin_account::AssociateAdminAccountInput).
    pub fn builder() -> crate::operation::associate_admin_account::builders::AssociateAdminAccountInputBuilder {
        crate::operation::associate_admin_account::builders::AssociateAdminAccountInputBuilder::default()
    }
}

/// A builder for [`AssociateAdminAccountInput`](crate::operation::associate_admin_account::AssociateAdminAccountInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateAdminAccountInputBuilder {
    pub(crate) admin_account: ::std::option::Option<::std::string::String>,
}
impl AssociateAdminAccountInputBuilder {
    /// <p>The Amazon Web Services account ID to associate with Firewall Manager as the Firewall Manager default administrator account. This account must be a member account of the organization in Organizations whose resources you want to protect. For more information about Organizations, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts.html">Managing the Amazon Web Services Accounts in Your Organization</a>.</p>
    /// This field is required.
    pub fn admin_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.admin_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID to associate with Firewall Manager as the Firewall Manager default administrator account. This account must be a member account of the organization in Organizations whose resources you want to protect. For more information about Organizations, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts.html">Managing the Amazon Web Services Accounts in Your Organization</a>.</p>
    pub fn set_admin_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.admin_account = input;
        self
    }
    /// <p>The Amazon Web Services account ID to associate with Firewall Manager as the Firewall Manager default administrator account. This account must be a member account of the organization in Organizations whose resources you want to protect. For more information about Organizations, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts.html">Managing the Amazon Web Services Accounts in Your Organization</a>.</p>
    pub fn get_admin_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.admin_account
    }
    /// Consumes the builder and constructs a [`AssociateAdminAccountInput`](crate::operation::associate_admin_account::AssociateAdminAccountInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::associate_admin_account::AssociateAdminAccountInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::associate_admin_account::AssociateAdminAccountInput {
            admin_account: self.admin_account,
        })
    }
}
