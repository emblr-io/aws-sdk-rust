// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeResourcePolicyOutput {
    /// <p>The JSON body of the resource-based policy.</p>
    pub resource_policy: ::std::option::Option<::std::string::String>,
    /// <p>The time at which the policy was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time at which the policy was last modified.</p>
    pub last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The revision ID of the policy. Each time you modify a policy, Amazon Comprehend assigns a new revision ID, and it deletes the prior version of the policy.</p>
    pub policy_revision_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeResourcePolicyOutput {
    /// <p>The JSON body of the resource-based policy.</p>
    pub fn resource_policy(&self) -> ::std::option::Option<&str> {
        self.resource_policy.as_deref()
    }
    /// <p>The time at which the policy was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The time at which the policy was last modified.</p>
    pub fn last_modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time.as_ref()
    }
    /// <p>The revision ID of the policy. Each time you modify a policy, Amazon Comprehend assigns a new revision ID, and it deletes the prior version of the policy.</p>
    pub fn policy_revision_id(&self) -> ::std::option::Option<&str> {
        self.policy_revision_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeResourcePolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeResourcePolicyOutput {
    /// Creates a new builder-style object to manufacture [`DescribeResourcePolicyOutput`](crate::operation::describe_resource_policy::DescribeResourcePolicyOutput).
    pub fn builder() -> crate::operation::describe_resource_policy::builders::DescribeResourcePolicyOutputBuilder {
        crate::operation::describe_resource_policy::builders::DescribeResourcePolicyOutputBuilder::default()
    }
}

/// A builder for [`DescribeResourcePolicyOutput`](crate::operation::describe_resource_policy::DescribeResourcePolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeResourcePolicyOutputBuilder {
    pub(crate) resource_policy: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) policy_revision_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeResourcePolicyOutputBuilder {
    /// <p>The JSON body of the resource-based policy.</p>
    pub fn resource_policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The JSON body of the resource-based policy.</p>
    pub fn set_resource_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_policy = input;
        self
    }
    /// <p>The JSON body of the resource-based policy.</p>
    pub fn get_resource_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_policy
    }
    /// <p>The time at which the policy was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the policy was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time at which the policy was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The time at which the policy was last modified.</p>
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the policy was last modified.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The time at which the policy was last modified.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// <p>The revision ID of the policy. Each time you modify a policy, Amazon Comprehend assigns a new revision ID, and it deletes the prior version of the policy.</p>
    pub fn policy_revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The revision ID of the policy. Each time you modify a policy, Amazon Comprehend assigns a new revision ID, and it deletes the prior version of the policy.</p>
    pub fn set_policy_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_revision_id = input;
        self
    }
    /// <p>The revision ID of the policy. Each time you modify a policy, Amazon Comprehend assigns a new revision ID, and it deletes the prior version of the policy.</p>
    pub fn get_policy_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_revision_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeResourcePolicyOutput`](crate::operation::describe_resource_policy::DescribeResourcePolicyOutput).
    pub fn build(self) -> crate::operation::describe_resource_policy::DescribeResourcePolicyOutput {
        crate::operation::describe_resource_policy::DescribeResourcePolicyOutput {
            resource_policy: self.resource_policy,
            creation_time: self.creation_time,
            last_modified_time: self.last_modified_time,
            policy_revision_id: self.policy_revision_id,
            _request_id: self._request_id,
        }
    }
}
