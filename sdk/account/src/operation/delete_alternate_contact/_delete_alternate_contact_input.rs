// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAlternateContactInput {
    /// <p>Specifies which of the alternate contacts to delete.</p>
    pub alternate_contact_type: ::std::option::Option<crate::types::AlternateContactType>,
    /// <p>Specifies the 12 digit account ID number of the Amazon Web Services account that you want to access or modify with this operation.</p>
    /// <p>If you do not specify this parameter, it defaults to the Amazon Web Services account of the identity used to call the operation.</p>
    /// <p>To use this parameter, the caller must be an identity in the <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html#account">organization's management account</a> or a delegated administrator account, and the specified account ID must be a member account in the same organization. The organization must have <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html">all features enabled</a>, and the organization must have <a href="https://docs.aws.amazon.com/organizations/latest/userguide/using-orgs-trusted-access.html">trusted access</a> enabled for the Account Management service, and optionally a <a href="https://docs.aws.amazon.com/organizations/latest/userguide/using-orgs-delegated-admin.html">delegated admin</a> account assigned.</p><note>
    /// <p>The management account can't specify its own <code>AccountId</code>; it must call the operation in standalone context by not including the <code>AccountId</code> parameter.</p>
    /// </note>
    /// <p>To call this operation on an account that is not a member of an organization, then don't specify this parameter, and call the operation using an identity belonging to the account whose contacts you wish to retrieve or modify.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
}
impl DeleteAlternateContactInput {
    /// <p>Specifies which of the alternate contacts to delete.</p>
    pub fn alternate_contact_type(&self) -> ::std::option::Option<&crate::types::AlternateContactType> {
        self.alternate_contact_type.as_ref()
    }
    /// <p>Specifies the 12 digit account ID number of the Amazon Web Services account that you want to access or modify with this operation.</p>
    /// <p>If you do not specify this parameter, it defaults to the Amazon Web Services account of the identity used to call the operation.</p>
    /// <p>To use this parameter, the caller must be an identity in the <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html#account">organization's management account</a> or a delegated administrator account, and the specified account ID must be a member account in the same organization. The organization must have <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html">all features enabled</a>, and the organization must have <a href="https://docs.aws.amazon.com/organizations/latest/userguide/using-orgs-trusted-access.html">trusted access</a> enabled for the Account Management service, and optionally a <a href="https://docs.aws.amazon.com/organizations/latest/userguide/using-orgs-delegated-admin.html">delegated admin</a> account assigned.</p><note>
    /// <p>The management account can't specify its own <code>AccountId</code>; it must call the operation in standalone context by not including the <code>AccountId</code> parameter.</p>
    /// </note>
    /// <p>To call this operation on an account that is not a member of an organization, then don't specify this parameter, and call the operation using an identity belonging to the account whose contacts you wish to retrieve or modify.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
}
impl DeleteAlternateContactInput {
    /// Creates a new builder-style object to manufacture [`DeleteAlternateContactInput`](crate::operation::delete_alternate_contact::DeleteAlternateContactInput).
    pub fn builder() -> crate::operation::delete_alternate_contact::builders::DeleteAlternateContactInputBuilder {
        crate::operation::delete_alternate_contact::builders::DeleteAlternateContactInputBuilder::default()
    }
}

/// A builder for [`DeleteAlternateContactInput`](crate::operation::delete_alternate_contact::DeleteAlternateContactInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAlternateContactInputBuilder {
    pub(crate) alternate_contact_type: ::std::option::Option<crate::types::AlternateContactType>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
}
impl DeleteAlternateContactInputBuilder {
    /// <p>Specifies which of the alternate contacts to delete.</p>
    /// This field is required.
    pub fn alternate_contact_type(mut self, input: crate::types::AlternateContactType) -> Self {
        self.alternate_contact_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies which of the alternate contacts to delete.</p>
    pub fn set_alternate_contact_type(mut self, input: ::std::option::Option<crate::types::AlternateContactType>) -> Self {
        self.alternate_contact_type = input;
        self
    }
    /// <p>Specifies which of the alternate contacts to delete.</p>
    pub fn get_alternate_contact_type(&self) -> &::std::option::Option<crate::types::AlternateContactType> {
        &self.alternate_contact_type
    }
    /// <p>Specifies the 12 digit account ID number of the Amazon Web Services account that you want to access or modify with this operation.</p>
    /// <p>If you do not specify this parameter, it defaults to the Amazon Web Services account of the identity used to call the operation.</p>
    /// <p>To use this parameter, the caller must be an identity in the <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html#account">organization's management account</a> or a delegated administrator account, and the specified account ID must be a member account in the same organization. The organization must have <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html">all features enabled</a>, and the organization must have <a href="https://docs.aws.amazon.com/organizations/latest/userguide/using-orgs-trusted-access.html">trusted access</a> enabled for the Account Management service, and optionally a <a href="https://docs.aws.amazon.com/organizations/latest/userguide/using-orgs-delegated-admin.html">delegated admin</a> account assigned.</p><note>
    /// <p>The management account can't specify its own <code>AccountId</code>; it must call the operation in standalone context by not including the <code>AccountId</code> parameter.</p>
    /// </note>
    /// <p>To call this operation on an account that is not a member of an organization, then don't specify this parameter, and call the operation using an identity belonging to the account whose contacts you wish to retrieve or modify.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the 12 digit account ID number of the Amazon Web Services account that you want to access or modify with this operation.</p>
    /// <p>If you do not specify this parameter, it defaults to the Amazon Web Services account of the identity used to call the operation.</p>
    /// <p>To use this parameter, the caller must be an identity in the <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html#account">organization's management account</a> or a delegated administrator account, and the specified account ID must be a member account in the same organization. The organization must have <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html">all features enabled</a>, and the organization must have <a href="https://docs.aws.amazon.com/organizations/latest/userguide/using-orgs-trusted-access.html">trusted access</a> enabled for the Account Management service, and optionally a <a href="https://docs.aws.amazon.com/organizations/latest/userguide/using-orgs-delegated-admin.html">delegated admin</a> account assigned.</p><note>
    /// <p>The management account can't specify its own <code>AccountId</code>; it must call the operation in standalone context by not including the <code>AccountId</code> parameter.</p>
    /// </note>
    /// <p>To call this operation on an account that is not a member of an organization, then don't specify this parameter, and call the operation using an identity belonging to the account whose contacts you wish to retrieve or modify.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>Specifies the 12 digit account ID number of the Amazon Web Services account that you want to access or modify with this operation.</p>
    /// <p>If you do not specify this parameter, it defaults to the Amazon Web Services account of the identity used to call the operation.</p>
    /// <p>To use this parameter, the caller must be an identity in the <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_getting-started_concepts.html#account">organization's management account</a> or a delegated administrator account, and the specified account ID must be a member account in the same organization. The organization must have <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html">all features enabled</a>, and the organization must have <a href="https://docs.aws.amazon.com/organizations/latest/userguide/using-orgs-trusted-access.html">trusted access</a> enabled for the Account Management service, and optionally a <a href="https://docs.aws.amazon.com/organizations/latest/userguide/using-orgs-delegated-admin.html">delegated admin</a> account assigned.</p><note>
    /// <p>The management account can't specify its own <code>AccountId</code>; it must call the operation in standalone context by not including the <code>AccountId</code> parameter.</p>
    /// </note>
    /// <p>To call this operation on an account that is not a member of an organization, then don't specify this parameter, and call the operation using an identity belonging to the account whose contacts you wish to retrieve or modify.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// Consumes the builder and constructs a [`DeleteAlternateContactInput`](crate::operation::delete_alternate_contact::DeleteAlternateContactInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_alternate_contact::DeleteAlternateContactInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_alternate_contact::DeleteAlternateContactInput {
            alternate_contact_type: self.alternate_contact_type,
            account_id: self.account_id,
        })
    }
}
