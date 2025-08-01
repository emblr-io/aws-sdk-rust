// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a managed policy.</p>
/// <p>This data type is used as a response element in the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicy.html">CreatePolicy</a>, <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicy.html">GetPolicy</a>, and <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html">ListPolicies</a> operations.</p>
/// <p>For more information about managed policies, refer to <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/policies-managed-vs-inline.html">Managed policies and inline policies</a> in the <i>IAM User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Policy {
    /// <p>The friendly name (not ARN) identifying the policy.</p>
    pub policy_name: ::std::option::Option<::std::string::String>,
    /// <p>The stable and unique string identifying the policy.</p>
    /// <p>For more information about IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub policy_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN). ARNs are unique identifiers for Amazon Web Services resources.</p>
    /// <p>For more information about ARNs, go to <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The path to the policy.</p>
    /// <p>For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub path: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the version of the policy that is set as the default version.</p>
    pub default_version_id: ::std::option::Option<::std::string::String>,
    /// <p>The number of entities (users, groups, and roles) that the policy is attached to.</p>
    pub attachment_count: ::std::option::Option<i32>,
    /// <p>The number of entities (users and roles) for which the policy is used to set the permissions boundary.</p>
    /// <p>For more information about permissions boundaries, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM identities </a> in the <i>IAM User Guide</i>.</p>
    pub permissions_boundary_usage_count: ::std::option::Option<i32>,
    /// <p>Specifies whether the policy can be attached to an IAM user, group, or role.</p>
    pub is_attachable: bool,
    /// <p>A friendly description of the policy.</p>
    /// <p>This element is included in the response to the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicy.html">GetPolicy</a> operation. It is not included in the response to the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html">ListPolicies</a> operation.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the policy was created.</p>
    pub create_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the policy was last updated.</p>
    /// <p>When a policy has only one version, this field contains the date and time when the policy was created. When a policy has more than one version, this field contains the date and time when the most recent policy version was created.</p>
    pub update_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A list of tags that are attached to the instance profile. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl Policy {
    /// <p>The friendly name (not ARN) identifying the policy.</p>
    pub fn policy_name(&self) -> ::std::option::Option<&str> {
        self.policy_name.as_deref()
    }
    /// <p>The stable and unique string identifying the policy.</p>
    /// <p>For more information about IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn policy_id(&self) -> ::std::option::Option<&str> {
        self.policy_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN). ARNs are unique identifiers for Amazon Web Services resources.</p>
    /// <p>For more information about ARNs, go to <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The path to the policy.</p>
    /// <p>For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn path(&self) -> ::std::option::Option<&str> {
        self.path.as_deref()
    }
    /// <p>The identifier for the version of the policy that is set as the default version.</p>
    pub fn default_version_id(&self) -> ::std::option::Option<&str> {
        self.default_version_id.as_deref()
    }
    /// <p>The number of entities (users, groups, and roles) that the policy is attached to.</p>
    pub fn attachment_count(&self) -> ::std::option::Option<i32> {
        self.attachment_count
    }
    /// <p>The number of entities (users and roles) for which the policy is used to set the permissions boundary.</p>
    /// <p>For more information about permissions boundaries, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM identities </a> in the <i>IAM User Guide</i>.</p>
    pub fn permissions_boundary_usage_count(&self) -> ::std::option::Option<i32> {
        self.permissions_boundary_usage_count
    }
    /// <p>Specifies whether the policy can be attached to an IAM user, group, or role.</p>
    pub fn is_attachable(&self) -> bool {
        self.is_attachable
    }
    /// <p>A friendly description of the policy.</p>
    /// <p>This element is included in the response to the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicy.html">GetPolicy</a> operation. It is not included in the response to the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html">ListPolicies</a> operation.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the policy was created.</p>
    pub fn create_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.create_date.as_ref()
    }
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the policy was last updated.</p>
    /// <p>When a policy has only one version, this field contains the date and time when the policy was created. When a policy has more than one version, this field contains the date and time when the most recent policy version was created.</p>
    pub fn update_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.update_date.as_ref()
    }
    /// <p>A list of tags that are attached to the instance profile. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl Policy {
    /// Creates a new builder-style object to manufacture [`Policy`](crate::types::Policy).
    pub fn builder() -> crate::types::builders::PolicyBuilder {
        crate::types::builders::PolicyBuilder::default()
    }
}

/// A builder for [`Policy`](crate::types::Policy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PolicyBuilder {
    pub(crate) policy_name: ::std::option::Option<::std::string::String>,
    pub(crate) policy_id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) path: ::std::option::Option<::std::string::String>,
    pub(crate) default_version_id: ::std::option::Option<::std::string::String>,
    pub(crate) attachment_count: ::std::option::Option<i32>,
    pub(crate) permissions_boundary_usage_count: ::std::option::Option<i32>,
    pub(crate) is_attachable: ::std::option::Option<bool>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) create_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) update_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl PolicyBuilder {
    /// <p>The friendly name (not ARN) identifying the policy.</p>
    pub fn policy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The friendly name (not ARN) identifying the policy.</p>
    pub fn set_policy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_name = input;
        self
    }
    /// <p>The friendly name (not ARN) identifying the policy.</p>
    pub fn get_policy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_name
    }
    /// <p>The stable and unique string identifying the policy.</p>
    /// <p>For more information about IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn policy_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The stable and unique string identifying the policy.</p>
    /// <p>For more information about IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn set_policy_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_id = input;
        self
    }
    /// <p>The stable and unique string identifying the policy.</p>
    /// <p>For more information about IDs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn get_policy_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_id
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
    /// <p>The path to the policy.</p>
    /// <p>For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to the policy.</p>
    /// <p>For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn set_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.path = input;
        self
    }
    /// <p>The path to the policy.</p>
    /// <p>For more information about paths, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/Using_Identifiers.html">IAM identifiers</a> in the <i>IAM User Guide</i>.</p>
    pub fn get_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.path
    }
    /// <p>The identifier for the version of the policy that is set as the default version.</p>
    pub fn default_version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the version of the policy that is set as the default version.</p>
    pub fn set_default_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_version_id = input;
        self
    }
    /// <p>The identifier for the version of the policy that is set as the default version.</p>
    pub fn get_default_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_version_id
    }
    /// <p>The number of entities (users, groups, and roles) that the policy is attached to.</p>
    pub fn attachment_count(mut self, input: i32) -> Self {
        self.attachment_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of entities (users, groups, and roles) that the policy is attached to.</p>
    pub fn set_attachment_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.attachment_count = input;
        self
    }
    /// <p>The number of entities (users, groups, and roles) that the policy is attached to.</p>
    pub fn get_attachment_count(&self) -> &::std::option::Option<i32> {
        &self.attachment_count
    }
    /// <p>The number of entities (users and roles) for which the policy is used to set the permissions boundary.</p>
    /// <p>For more information about permissions boundaries, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM identities </a> in the <i>IAM User Guide</i>.</p>
    pub fn permissions_boundary_usage_count(mut self, input: i32) -> Self {
        self.permissions_boundary_usage_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of entities (users and roles) for which the policy is used to set the permissions boundary.</p>
    /// <p>For more information about permissions boundaries, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM identities </a> in the <i>IAM User Guide</i>.</p>
    pub fn set_permissions_boundary_usage_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.permissions_boundary_usage_count = input;
        self
    }
    /// <p>The number of entities (users and roles) for which the policy is used to set the permissions boundary.</p>
    /// <p>For more information about permissions boundaries, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html">Permissions boundaries for IAM identities </a> in the <i>IAM User Guide</i>.</p>
    pub fn get_permissions_boundary_usage_count(&self) -> &::std::option::Option<i32> {
        &self.permissions_boundary_usage_count
    }
    /// <p>Specifies whether the policy can be attached to an IAM user, group, or role.</p>
    pub fn is_attachable(mut self, input: bool) -> Self {
        self.is_attachable = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the policy can be attached to an IAM user, group, or role.</p>
    pub fn set_is_attachable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_attachable = input;
        self
    }
    /// <p>Specifies whether the policy can be attached to an IAM user, group, or role.</p>
    pub fn get_is_attachable(&self) -> &::std::option::Option<bool> {
        &self.is_attachable
    }
    /// <p>A friendly description of the policy.</p>
    /// <p>This element is included in the response to the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicy.html">GetPolicy</a> operation. It is not included in the response to the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html">ListPolicies</a> operation.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A friendly description of the policy.</p>
    /// <p>This element is included in the response to the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicy.html">GetPolicy</a> operation. It is not included in the response to the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html">ListPolicies</a> operation.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A friendly description of the policy.</p>
    /// <p>This element is included in the response to the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetPolicy.html">GetPolicy</a> operation. It is not included in the response to the <a href="https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListPolicies.html">ListPolicies</a> operation.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the policy was created.</p>
    pub fn create_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the policy was created.</p>
    pub fn set_create_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_date = input;
        self
    }
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the policy was created.</p>
    pub fn get_create_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_date
    }
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the policy was last updated.</p>
    /// <p>When a policy has only one version, this field contains the date and time when the policy was created. When a policy has more than one version, this field contains the date and time when the most recent policy version was created.</p>
    pub fn update_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.update_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the policy was last updated.</p>
    /// <p>When a policy has only one version, this field contains the date and time when the policy was created. When a policy has more than one version, this field contains the date and time when the most recent policy version was created.</p>
    pub fn set_update_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.update_date = input;
        self
    }
    /// <p>The date and time, in <a href="http://www.iso.org/iso/iso8601">ISO 8601 date-time format</a>, when the policy was last updated.</p>
    /// <p>When a policy has only one version, this field contains the date and time when the policy was created. When a policy has more than one version, this field contains the date and time when the most recent policy version was created.</p>
    pub fn get_update_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.update_date
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags that are attached to the instance profile. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags that are attached to the instance profile. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags that are attached to the instance profile. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`Policy`](crate::types::Policy).
    pub fn build(self) -> crate::types::Policy {
        crate::types::Policy {
            policy_name: self.policy_name,
            policy_id: self.policy_id,
            arn: self.arn,
            path: self.path,
            default_version_id: self.default_version_id,
            attachment_count: self.attachment_count,
            permissions_boundary_usage_count: self.permissions_boundary_usage_count,
            is_attachable: self.is_attachable.unwrap_or_default(),
            description: self.description,
            create_date: self.create_date,
            update_date: self.update_date,
            tags: self.tags,
        }
    }
}
