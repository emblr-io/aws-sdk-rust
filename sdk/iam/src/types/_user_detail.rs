// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about an IAM user, including all the user's policies and all the IAM groups the user is in.</p>
/// <p>This data type is used as a response element in the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html">GetAccountAuthorizationDetails</a> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UserDetail {
    /// <p>The path to the user. For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub path: ::std::option::Option<::std::string::String>,
    /// <p>The friendly name identifying the user.</p>
    pub user_name: ::std::option::Option<::std::string::String>,
    /// <p>The stable and unique string identifying the user. For more information about IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub user_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN). ARNs are unique identifiers for Amazon Web Services resources.</p>
    /// <p>For more information about ARNs, go to <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the user was created.</p>
    pub create_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A list of the inline policies embedded in the user.</p>
    pub user_policy_list: ::std::option::Option<::std::vec::Vec<crate::types::PolicyDetail>>,
    /// <p>A list of IAM groups that the user is in.</p>
    pub group_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of the managed policies attached to the user.</p>
    pub attached_managed_policies: ::std::option::Option<::std::vec::Vec<crate::types::AttachedPolicy>>,
    /// <p>The ARN of the policy used to set the permissions boundary for the user.</p>
    /// <p>For more information about permissions boundaries, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM identities </a> in the <i>IAM User Guide</i>.</p>
    pub permissions_boundary: ::std::option::Option<crate::types::AttachedPermissionsBoundary>,
    /// <p>A list of tags that are associated with the user. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl UserDetail {
    /// <p>The path to the user. For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn path(&self) -> ::std::option::Option<&str> {
        self.path.as_deref()
    }
    /// <p>The friendly name identifying the user.</p>
    pub fn user_name(&self) -> ::std::option::Option<&str> {
        self.user_name.as_deref()
    }
    /// <p>The stable and unique string identifying the user. For more information about IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn user_id(&self) -> ::std::option::Option<&str> {
        self.user_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN). ARNs are unique identifiers for Amazon Web Services resources.</p>
    /// <p>For more information about ARNs, go to <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the user was created.</p>
    pub fn create_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.create_date.as_ref()
    }
    /// <p>A list of the inline policies embedded in the user.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_policy_list.is_none()`.
    pub fn user_policy_list(&self) -> &[crate::types::PolicyDetail] {
        self.user_policy_list.as_deref().unwrap_or_default()
    }
    /// <p>A list of IAM groups that the user is in.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.group_list.is_none()`.
    pub fn group_list(&self) -> &[::std::string::String] {
        self.group_list.as_deref().unwrap_or_default()
    }
    /// <p>A list of the managed policies attached to the user.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attached_managed_policies.is_none()`.
    pub fn attached_managed_policies(&self) -> &[crate::types::AttachedPolicy] {
        self.attached_managed_policies.as_deref().unwrap_or_default()
    }
    /// <p>The ARN of the policy used to set the permissions boundary for the user.</p>
    /// <p>For more information about permissions boundaries, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM identities </a> in the <i>IAM User Guide</i>.</p>
    pub fn permissions_boundary(&self) -> ::std::option::Option<&crate::types::AttachedPermissionsBoundary> {
        self.permissions_boundary.as_ref()
    }
    /// <p>A list of tags that are associated with the user. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl UserDetail {
    /// Creates a new builder-style object to manufacture [`UserDetail`](crate::types::UserDetail).
    pub fn builder() -> crate::types::builders::UserDetailBuilder {
        crate::types::builders::UserDetailBuilder::default()
    }
}

/// A builder for [`UserDetail`](crate::types::UserDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UserDetailBuilder {
    pub(crate) path: ::std::option::Option<::std::string::String>,
    pub(crate) user_name: ::std::option::Option<::std::string::String>,
    pub(crate) user_id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) create_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) user_policy_list: ::std::option::Option<::std::vec::Vec<crate::types::PolicyDetail>>,
    pub(crate) group_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) attached_managed_policies: ::std::option::Option<::std::vec::Vec<crate::types::AttachedPolicy>>,
    pub(crate) permissions_boundary: ::std::option::Option<crate::types::AttachedPermissionsBoundary>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl UserDetailBuilder {
    /// <p>The path to the user. For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to the user. For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn set_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.path = input;
        self
    }
    /// <p>The path to the user. For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn get_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.path
    }
    /// <p>The friendly name identifying the user.</p>
    pub fn user_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The friendly name identifying the user.</p>
    pub fn set_user_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_name = input;
        self
    }
    /// <p>The friendly name identifying the user.</p>
    pub fn get_user_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_name
    }
    /// <p>The stable and unique string identifying the user. For more information about IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn user_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The stable and unique string identifying the user. For more information about IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn set_user_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_id = input;
        self
    }
    /// <p>The stable and unique string identifying the user. For more information about IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn get_user_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_id
    }
    /// <p>The Amazon Resource Name (ARN). ARNs are unique identifiers for Amazon Web Services resources.</p>
    /// <p>For more information about ARNs, go to <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN). ARNs are unique identifiers for Amazon Web Services resources.</p>
    /// <p>For more information about ARNs, go to <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN). ARNs are unique identifiers for Amazon Web Services resources.</p>
    /// <p>For more information about ARNs, go to <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the user was created.</p>
    pub fn create_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the user was created.</p>
    pub fn set_create_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_date = input;
        self
    }
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the user was created.</p>
    pub fn get_create_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_date
    }
    /// Appends an item to `user_policy_list`.
    ///
    /// To override the contents of this collection use [`set_user_policy_list`](Self::set_user_policy_list).
    ///
    /// <p>A list of the inline policies embedded in the user.</p>
    pub fn user_policy_list(mut self, input: crate::types::PolicyDetail) -> Self {
        let mut v = self.user_policy_list.unwrap_or_default();
        v.push(input);
        self.user_policy_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the inline policies embedded in the user.</p>
    pub fn set_user_policy_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PolicyDetail>>) -> Self {
        self.user_policy_list = input;
        self
    }
    /// <p>A list of the inline policies embedded in the user.</p>
    pub fn get_user_policy_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PolicyDetail>> {
        &self.user_policy_list
    }
    /// Appends an item to `group_list`.
    ///
    /// To override the contents of this collection use [`set_group_list`](Self::set_group_list).
    ///
    /// <p>A list of IAM groups that the user is in.</p>
    pub fn group_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.group_list.unwrap_or_default();
        v.push(input.into());
        self.group_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of IAM groups that the user is in.</p>
    pub fn set_group_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.group_list = input;
        self
    }
    /// <p>A list of IAM groups that the user is in.</p>
    pub fn get_group_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.group_list
    }
    /// Appends an item to `attached_managed_policies`.
    ///
    /// To override the contents of this collection use [`set_attached_managed_policies`](Self::set_attached_managed_policies).
    ///
    /// <p>A list of the managed policies attached to the user.</p>
    pub fn attached_managed_policies(mut self, input: crate::types::AttachedPolicy) -> Self {
        let mut v = self.attached_managed_policies.unwrap_or_default();
        v.push(input);
        self.attached_managed_policies = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the managed policies attached to the user.</p>
    pub fn set_attached_managed_policies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AttachedPolicy>>) -> Self {
        self.attached_managed_policies = input;
        self
    }
    /// <p>A list of the managed policies attached to the user.</p>
    pub fn get_attached_managed_policies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AttachedPolicy>> {
        &self.attached_managed_policies
    }
    /// <p>The ARN of the policy used to set the permissions boundary for the user.</p>
    /// <p>For more information about permissions boundaries, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM identities </a> in the <i>IAM User Guide</i>.</p>
    pub fn permissions_boundary(mut self, input: crate::types::AttachedPermissionsBoundary) -> Self {
        self.permissions_boundary = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ARN of the policy used to set the permissions boundary for the user.</p>
    /// <p>For more information about permissions boundaries, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM identities </a> in the <i>IAM User Guide</i>.</p>
    pub fn set_permissions_boundary(mut self, input: ::std::option::Option<crate::types::AttachedPermissionsBoundary>) -> Self {
        self.permissions_boundary = input;
        self
    }
    /// <p>The ARN of the policy used to set the permissions boundary for the user.</p>
    /// <p>For more information about permissions boundaries, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM identities </a> in the <i>IAM User Guide</i>.</p>
    pub fn get_permissions_boundary(&self) -> &::std::option::Option<crate::types::AttachedPermissionsBoundary> {
        &self.permissions_boundary
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags that are associated with the user. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags that are associated with the user. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags that are associated with the user. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`UserDetail`](crate::types::UserDetail).
    pub fn build(self) -> crate::types::UserDetail {
        crate::types::UserDetail {
            path: self.path,
            user_name: self.user_name,
            user_id: self.user_id,
            arn: self.arn,
            create_date: self.create_date,
            user_policy_list: self.user_policy_list,
            group_list: self.group_list,
            attached_managed_policies: self.attached_managed_policies,
            permissions_boundary: self.permissions_boundary,
            tags: self.tags,
        }
    }
}
