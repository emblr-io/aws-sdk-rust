// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct InviteAccountToOrganizationInput {
    /// <p>The identifier (ID) of the Amazon Web Services account that you want to invite to join your organization. This is a JSON object that contains the following elements:</p>
    /// <p><code>{ "Type": "ACCOUNT", "Id": "&lt;<i> <b>account id number</b> </i>&gt;" }</code></p>
    /// <p>If you use the CLI, you can submit this as a single string, similar to the following example:</p>
    /// <p><code>--target Id=123456789012,Type=ACCOUNT</code></p>
    /// <p>If you specify <code>"Type": "ACCOUNT"</code>, you must provide the Amazon Web Services account ID number as the <code>Id</code>. If you specify <code>"Type": "EMAIL"</code>, you must specify the email address that is associated with the account.</p>
    /// <p><code>--target Id=diego@example.com,Type=EMAIL</code></p>
    pub target: ::std::option::Option<crate::types::HandshakeParty>,
    /// <p>Additional information that you want to include in the generated email to the recipient account owner.</p>
    pub notes: ::std::option::Option<::std::string::String>,
    /// <p>A list of tags that you want to attach to the account when it becomes a member of the organization. For each tag in the list, you must specify both a tag key and a value. You can set the value to an empty string, but you can't set it to <code>null</code>. For more information about tagging, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_tagging.html">Tagging Organizations resources</a> in the Organizations User Guide.</p><important>
    /// <p>Any tags in the request are checked for compliance with any applicable tag policies when the request is made. The request is rejected if the tags in the request don't match the requirements of the policy at that time. Tag policy compliance is <i> <b>not</b> </i> checked again when the invitation is accepted and the tags are actually attached to the account. That means that if the tag policy changes between the invitation and the acceptance, then that tags could potentially be non-compliant.</p>
    /// </important> <note>
    /// <p>If any one of the tags is not valid or if you exceed the allowed number of tags for an account, then the entire request fails and invitations are not sent.</p>
    /// </note>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl InviteAccountToOrganizationInput {
    /// <p>The identifier (ID) of the Amazon Web Services account that you want to invite to join your organization. This is a JSON object that contains the following elements:</p>
    /// <p><code>{ "Type": "ACCOUNT", "Id": "&lt;<i> <b>account id number</b> </i>&gt;" }</code></p>
    /// <p>If you use the CLI, you can submit this as a single string, similar to the following example:</p>
    /// <p><code>--target Id=123456789012,Type=ACCOUNT</code></p>
    /// <p>If you specify <code>"Type": "ACCOUNT"</code>, you must provide the Amazon Web Services account ID number as the <code>Id</code>. If you specify <code>"Type": "EMAIL"</code>, you must specify the email address that is associated with the account.</p>
    /// <p><code>--target Id=diego@example.com,Type=EMAIL</code></p>
    pub fn target(&self) -> ::std::option::Option<&crate::types::HandshakeParty> {
        self.target.as_ref()
    }
    /// <p>Additional information that you want to include in the generated email to the recipient account owner.</p>
    pub fn notes(&self) -> ::std::option::Option<&str> {
        self.notes.as_deref()
    }
    /// <p>A list of tags that you want to attach to the account when it becomes a member of the organization. For each tag in the list, you must specify both a tag key and a value. You can set the value to an empty string, but you can't set it to <code>null</code>. For more information about tagging, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_tagging.html">Tagging Organizations resources</a> in the Organizations User Guide.</p><important>
    /// <p>Any tags in the request are checked for compliance with any applicable tag policies when the request is made. The request is rejected if the tags in the request don't match the requirements of the policy at that time. Tag policy compliance is <i> <b>not</b> </i> checked again when the invitation is accepted and the tags are actually attached to the account. That means that if the tag policy changes between the invitation and the acceptance, then that tags could potentially be non-compliant.</p>
    /// </important> <note>
    /// <p>If any one of the tags is not valid or if you exceed the allowed number of tags for an account, then the entire request fails and invitations are not sent.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for InviteAccountToOrganizationInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InviteAccountToOrganizationInput");
        formatter.field("target", &self.target);
        formatter.field("notes", &"*** Sensitive Data Redacted ***");
        formatter.field("tags", &self.tags);
        formatter.finish()
    }
}
impl InviteAccountToOrganizationInput {
    /// Creates a new builder-style object to manufacture [`InviteAccountToOrganizationInput`](crate::operation::invite_account_to_organization::InviteAccountToOrganizationInput).
    pub fn builder() -> crate::operation::invite_account_to_organization::builders::InviteAccountToOrganizationInputBuilder {
        crate::operation::invite_account_to_organization::builders::InviteAccountToOrganizationInputBuilder::default()
    }
}

/// A builder for [`InviteAccountToOrganizationInput`](crate::operation::invite_account_to_organization::InviteAccountToOrganizationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct InviteAccountToOrganizationInputBuilder {
    pub(crate) target: ::std::option::Option<crate::types::HandshakeParty>,
    pub(crate) notes: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl InviteAccountToOrganizationInputBuilder {
    /// <p>The identifier (ID) of the Amazon Web Services account that you want to invite to join your organization. This is a JSON object that contains the following elements:</p>
    /// <p><code>{ "Type": "ACCOUNT", "Id": "&lt;<i> <b>account id number</b> </i>&gt;" }</code></p>
    /// <p>If you use the CLI, you can submit this as a single string, similar to the following example:</p>
    /// <p><code>--target Id=123456789012,Type=ACCOUNT</code></p>
    /// <p>If you specify <code>"Type": "ACCOUNT"</code>, you must provide the Amazon Web Services account ID number as the <code>Id</code>. If you specify <code>"Type": "EMAIL"</code>, you must specify the email address that is associated with the account.</p>
    /// <p><code>--target Id=diego@example.com,Type=EMAIL</code></p>
    /// This field is required.
    pub fn target(mut self, input: crate::types::HandshakeParty) -> Self {
        self.target = ::std::option::Option::Some(input);
        self
    }
    /// <p>The identifier (ID) of the Amazon Web Services account that you want to invite to join your organization. This is a JSON object that contains the following elements:</p>
    /// <p><code>{ "Type": "ACCOUNT", "Id": "&lt;<i> <b>account id number</b> </i>&gt;" }</code></p>
    /// <p>If you use the CLI, you can submit this as a single string, similar to the following example:</p>
    /// <p><code>--target Id=123456789012,Type=ACCOUNT</code></p>
    /// <p>If you specify <code>"Type": "ACCOUNT"</code>, you must provide the Amazon Web Services account ID number as the <code>Id</code>. If you specify <code>"Type": "EMAIL"</code>, you must specify the email address that is associated with the account.</p>
    /// <p><code>--target Id=diego@example.com,Type=EMAIL</code></p>
    pub fn set_target(mut self, input: ::std::option::Option<crate::types::HandshakeParty>) -> Self {
        self.target = input;
        self
    }
    /// <p>The identifier (ID) of the Amazon Web Services account that you want to invite to join your organization. This is a JSON object that contains the following elements:</p>
    /// <p><code>{ "Type": "ACCOUNT", "Id": "&lt;<i> <b>account id number</b> </i>&gt;" }</code></p>
    /// <p>If you use the CLI, you can submit this as a single string, similar to the following example:</p>
    /// <p><code>--target Id=123456789012,Type=ACCOUNT</code></p>
    /// <p>If you specify <code>"Type": "ACCOUNT"</code>, you must provide the Amazon Web Services account ID number as the <code>Id</code>. If you specify <code>"Type": "EMAIL"</code>, you must specify the email address that is associated with the account.</p>
    /// <p><code>--target Id=diego@example.com,Type=EMAIL</code></p>
    pub fn get_target(&self) -> &::std::option::Option<crate::types::HandshakeParty> {
        &self.target
    }
    /// <p>Additional information that you want to include in the generated email to the recipient account owner.</p>
    pub fn notes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.notes = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Additional information that you want to include in the generated email to the recipient account owner.</p>
    pub fn set_notes(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.notes = input;
        self
    }
    /// <p>Additional information that you want to include in the generated email to the recipient account owner.</p>
    pub fn get_notes(&self) -> &::std::option::Option<::std::string::String> {
        &self.notes
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags that you want to attach to the account when it becomes a member of the organization. For each tag in the list, you must specify both a tag key and a value. You can set the value to an empty string, but you can't set it to <code>null</code>. For more information about tagging, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_tagging.html">Tagging Organizations resources</a> in the Organizations User Guide.</p><important>
    /// <p>Any tags in the request are checked for compliance with any applicable tag policies when the request is made. The request is rejected if the tags in the request don't match the requirements of the policy at that time. Tag policy compliance is <i> <b>not</b> </i> checked again when the invitation is accepted and the tags are actually attached to the account. That means that if the tag policy changes between the invitation and the acceptance, then that tags could potentially be non-compliant.</p>
    /// </important> <note>
    /// <p>If any one of the tags is not valid or if you exceed the allowed number of tags for an account, then the entire request fails and invitations are not sent.</p>
    /// </note>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags that you want to attach to the account when it becomes a member of the organization. For each tag in the list, you must specify both a tag key and a value. You can set the value to an empty string, but you can't set it to <code>null</code>. For more information about tagging, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_tagging.html">Tagging Organizations resources</a> in the Organizations User Guide.</p><important>
    /// <p>Any tags in the request are checked for compliance with any applicable tag policies when the request is made. The request is rejected if the tags in the request don't match the requirements of the policy at that time. Tag policy compliance is <i> <b>not</b> </i> checked again when the invitation is accepted and the tags are actually attached to the account. That means that if the tag policy changes between the invitation and the acceptance, then that tags could potentially be non-compliant.</p>
    /// </important> <note>
    /// <p>If any one of the tags is not valid or if you exceed the allowed number of tags for an account, then the entire request fails and invitations are not sent.</p>
    /// </note>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags that you want to attach to the account when it becomes a member of the organization. For each tag in the list, you must specify both a tag key and a value. You can set the value to an empty string, but you can't set it to <code>null</code>. For more information about tagging, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_tagging.html">Tagging Organizations resources</a> in the Organizations User Guide.</p><important>
    /// <p>Any tags in the request are checked for compliance with any applicable tag policies when the request is made. The request is rejected if the tags in the request don't match the requirements of the policy at that time. Tag policy compliance is <i> <b>not</b> </i> checked again when the invitation is accepted and the tags are actually attached to the account. That means that if the tag policy changes between the invitation and the acceptance, then that tags could potentially be non-compliant.</p>
    /// </important> <note>
    /// <p>If any one of the tags is not valid or if you exceed the allowed number of tags for an account, then the entire request fails and invitations are not sent.</p>
    /// </note>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`InviteAccountToOrganizationInput`](crate::operation::invite_account_to_organization::InviteAccountToOrganizationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::invite_account_to_organization::InviteAccountToOrganizationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::invite_account_to_organization::InviteAccountToOrganizationInput {
            target: self.target,
            notes: self.notes,
            tags: self.tags,
        })
    }
}
impl ::std::fmt::Debug for InviteAccountToOrganizationInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InviteAccountToOrganizationInputBuilder");
        formatter.field("target", &self.target);
        formatter.field("notes", &"*** Sensitive Data Redacted ***");
        formatter.field("tags", &self.tags);
        formatter.finish()
    }
}
