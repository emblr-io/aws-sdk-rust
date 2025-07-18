// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about an IAM group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsIamGroupDetails {
    /// <p>A list of the managed policies that are attached to the IAM group.</p>
    pub attached_managed_policies: ::std::option::Option<::std::vec::Vec<crate::types::AwsIamAttachedManagedPolicy>>,
    /// <p>Indicates when the IAM group was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub create_date: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the IAM group.</p>
    pub group_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the IAM group.</p>
    pub group_name: ::std::option::Option<::std::string::String>,
    /// <p>The list of inline policies that are embedded in the group.</p>
    pub group_policy_list: ::std::option::Option<::std::vec::Vec<crate::types::AwsIamGroupPolicy>>,
    /// <p>The path to the group.</p>
    pub path: ::std::option::Option<::std::string::String>,
}
impl AwsIamGroupDetails {
    /// <p>A list of the managed policies that are attached to the IAM group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attached_managed_policies.is_none()`.
    pub fn attached_managed_policies(&self) -> &[crate::types::AwsIamAttachedManagedPolicy] {
        self.attached_managed_policies.as_deref().unwrap_or_default()
    }
    /// <p>Indicates when the IAM group was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn create_date(&self) -> ::std::option::Option<&str> {
        self.create_date.as_deref()
    }
    /// <p>The identifier of the IAM group.</p>
    pub fn group_id(&self) -> ::std::option::Option<&str> {
        self.group_id.as_deref()
    }
    /// <p>The name of the IAM group.</p>
    pub fn group_name(&self) -> ::std::option::Option<&str> {
        self.group_name.as_deref()
    }
    /// <p>The list of inline policies that are embedded in the group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.group_policy_list.is_none()`.
    pub fn group_policy_list(&self) -> &[crate::types::AwsIamGroupPolicy] {
        self.group_policy_list.as_deref().unwrap_or_default()
    }
    /// <p>The path to the group.</p>
    pub fn path(&self) -> ::std::option::Option<&str> {
        self.path.as_deref()
    }
}
impl AwsIamGroupDetails {
    /// Creates a new builder-style object to manufacture [`AwsIamGroupDetails`](crate::types::AwsIamGroupDetails).
    pub fn builder() -> crate::types::builders::AwsIamGroupDetailsBuilder {
        crate::types::builders::AwsIamGroupDetailsBuilder::default()
    }
}

/// A builder for [`AwsIamGroupDetails`](crate::types::AwsIamGroupDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsIamGroupDetailsBuilder {
    pub(crate) attached_managed_policies: ::std::option::Option<::std::vec::Vec<crate::types::AwsIamAttachedManagedPolicy>>,
    pub(crate) create_date: ::std::option::Option<::std::string::String>,
    pub(crate) group_id: ::std::option::Option<::std::string::String>,
    pub(crate) group_name: ::std::option::Option<::std::string::String>,
    pub(crate) group_policy_list: ::std::option::Option<::std::vec::Vec<crate::types::AwsIamGroupPolicy>>,
    pub(crate) path: ::std::option::Option<::std::string::String>,
}
impl AwsIamGroupDetailsBuilder {
    /// Appends an item to `attached_managed_policies`.
    ///
    /// To override the contents of this collection use [`set_attached_managed_policies`](Self::set_attached_managed_policies).
    ///
    /// <p>A list of the managed policies that are attached to the IAM group.</p>
    pub fn attached_managed_policies(mut self, input: crate::types::AwsIamAttachedManagedPolicy) -> Self {
        let mut v = self.attached_managed_policies.unwrap_or_default();
        v.push(input);
        self.attached_managed_policies = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the managed policies that are attached to the IAM group.</p>
    pub fn set_attached_managed_policies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AwsIamAttachedManagedPolicy>>) -> Self {
        self.attached_managed_policies = input;
        self
    }
    /// <p>A list of the managed policies that are attached to the IAM group.</p>
    pub fn get_attached_managed_policies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AwsIamAttachedManagedPolicy>> {
        &self.attached_managed_policies
    }
    /// <p>Indicates when the IAM group was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn create_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.create_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates when the IAM group was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn set_create_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.create_date = input;
        self
    }
    /// <p>Indicates when the IAM group was created.</p>
    /// <p>For more information about the validation and formatting of timestamp fields in Security Hub, see <a href="https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps">Timestamps</a>.</p>
    pub fn get_create_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.create_date
    }
    /// <p>The identifier of the IAM group.</p>
    pub fn group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the IAM group.</p>
    pub fn set_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_id = input;
        self
    }
    /// <p>The identifier of the IAM group.</p>
    pub fn get_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_id
    }
    /// <p>The name of the IAM group.</p>
    pub fn group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the IAM group.</p>
    pub fn set_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_name = input;
        self
    }
    /// <p>The name of the IAM group.</p>
    pub fn get_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_name
    }
    /// Appends an item to `group_policy_list`.
    ///
    /// To override the contents of this collection use [`set_group_policy_list`](Self::set_group_policy_list).
    ///
    /// <p>The list of inline policies that are embedded in the group.</p>
    pub fn group_policy_list(mut self, input: crate::types::AwsIamGroupPolicy) -> Self {
        let mut v = self.group_policy_list.unwrap_or_default();
        v.push(input);
        self.group_policy_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of inline policies that are embedded in the group.</p>
    pub fn set_group_policy_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AwsIamGroupPolicy>>) -> Self {
        self.group_policy_list = input;
        self
    }
    /// <p>The list of inline policies that are embedded in the group.</p>
    pub fn get_group_policy_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AwsIamGroupPolicy>> {
        &self.group_policy_list
    }
    /// <p>The path to the group.</p>
    pub fn path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to the group.</p>
    pub fn set_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.path = input;
        self
    }
    /// <p>The path to the group.</p>
    pub fn get_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.path
    }
    /// Consumes the builder and constructs a [`AwsIamGroupDetails`](crate::types::AwsIamGroupDetails).
    pub fn build(self) -> crate::types::AwsIamGroupDetails {
        crate::types::AwsIamGroupDetails {
            attached_managed_policies: self.attached_managed_policies,
            create_date: self.create_date,
            group_id: self.group_id,
            group_name: self.group_name,
            group_policy_list: self.group_policy_list,
            path: self.path,
        }
    }
}
