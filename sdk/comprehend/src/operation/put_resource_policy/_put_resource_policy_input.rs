// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutResourcePolicyInput {
    /// <p>The Amazon Resource Name (ARN) of the custom model to attach the policy to.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The JSON resource-based policy to attach to your custom model. Provide your JSON as a UTF-8 encoded string without line breaks. To provide valid JSON for your policy, enclose the attribute names and values in double quotes. If the JSON body is also enclosed in double quotes, then you must escape the double quotes that are inside the policy:</p>
    /// <p><code>"{\"attribute\": \"value\", \"attribute\": \[\"value\"\]}"</code></p>
    /// <p>To avoid escaping quotes, you can use single quotes to enclose the policy and double quotes to enclose the JSON names and values:</p>
    /// <p><code>'{"attribute": "value", "attribute": \["value"\]}'</code></p>
    pub resource_policy: ::std::option::Option<::std::string::String>,
    /// <p>The revision ID that Amazon Comprehend assigned to the policy that you are updating. If you are creating a new policy that has no prior version, don't use this parameter. Amazon Comprehend creates the revision ID for you.</p>
    pub policy_revision_id: ::std::option::Option<::std::string::String>,
}
impl PutResourcePolicyInput {
    /// <p>The Amazon Resource Name (ARN) of the custom model to attach the policy to.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The JSON resource-based policy to attach to your custom model. Provide your JSON as a UTF-8 encoded string without line breaks. To provide valid JSON for your policy, enclose the attribute names and values in double quotes. If the JSON body is also enclosed in double quotes, then you must escape the double quotes that are inside the policy:</p>
    /// <p><code>"{\"attribute\": \"value\", \"attribute\": \[\"value\"\]}"</code></p>
    /// <p>To avoid escaping quotes, you can use single quotes to enclose the policy and double quotes to enclose the JSON names and values:</p>
    /// <p><code>'{"attribute": "value", "attribute": \["value"\]}'</code></p>
    pub fn resource_policy(&self) -> ::std::option::Option<&str> {
        self.resource_policy.as_deref()
    }
    /// <p>The revision ID that Amazon Comprehend assigned to the policy that you are updating. If you are creating a new policy that has no prior version, don't use this parameter. Amazon Comprehend creates the revision ID for you.</p>
    pub fn policy_revision_id(&self) -> ::std::option::Option<&str> {
        self.policy_revision_id.as_deref()
    }
}
impl PutResourcePolicyInput {
    /// Creates a new builder-style object to manufacture [`PutResourcePolicyInput`](crate::operation::put_resource_policy::PutResourcePolicyInput).
    pub fn builder() -> crate::operation::put_resource_policy::builders::PutResourcePolicyInputBuilder {
        crate::operation::put_resource_policy::builders::PutResourcePolicyInputBuilder::default()
    }
}

/// A builder for [`PutResourcePolicyInput`](crate::operation::put_resource_policy::PutResourcePolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutResourcePolicyInputBuilder {
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_policy: ::std::option::Option<::std::string::String>,
    pub(crate) policy_revision_id: ::std::option::Option<::std::string::String>,
}
impl PutResourcePolicyInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the custom model to attach the policy to.</p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom model to attach the policy to.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom model to attach the policy to.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The JSON resource-based policy to attach to your custom model. Provide your JSON as a UTF-8 encoded string without line breaks. To provide valid JSON for your policy, enclose the attribute names and values in double quotes. If the JSON body is also enclosed in double quotes, then you must escape the double quotes that are inside the policy:</p>
    /// <p><code>"{\"attribute\": \"value\", \"attribute\": \[\"value\"\]}"</code></p>
    /// <p>To avoid escaping quotes, you can use single quotes to enclose the policy and double quotes to enclose the JSON names and values:</p>
    /// <p><code>'{"attribute": "value", "attribute": \["value"\]}'</code></p>
    /// This field is required.
    pub fn resource_policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The JSON resource-based policy to attach to your custom model. Provide your JSON as a UTF-8 encoded string without line breaks. To provide valid JSON for your policy, enclose the attribute names and values in double quotes. If the JSON body is also enclosed in double quotes, then you must escape the double quotes that are inside the policy:</p>
    /// <p><code>"{\"attribute\": \"value\", \"attribute\": \[\"value\"\]}"</code></p>
    /// <p>To avoid escaping quotes, you can use single quotes to enclose the policy and double quotes to enclose the JSON names and values:</p>
    /// <p><code>'{"attribute": "value", "attribute": \["value"\]}'</code></p>
    pub fn set_resource_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_policy = input;
        self
    }
    /// <p>The JSON resource-based policy to attach to your custom model. Provide your JSON as a UTF-8 encoded string without line breaks. To provide valid JSON for your policy, enclose the attribute names and values in double quotes. If the JSON body is also enclosed in double quotes, then you must escape the double quotes that are inside the policy:</p>
    /// <p><code>"{\"attribute\": \"value\", \"attribute\": \[\"value\"\]}"</code></p>
    /// <p>To avoid escaping quotes, you can use single quotes to enclose the policy and double quotes to enclose the JSON names and values:</p>
    /// <p><code>'{"attribute": "value", "attribute": \["value"\]}'</code></p>
    pub fn get_resource_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_policy
    }
    /// <p>The revision ID that Amazon Comprehend assigned to the policy that you are updating. If you are creating a new policy that has no prior version, don't use this parameter. Amazon Comprehend creates the revision ID for you.</p>
    pub fn policy_revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The revision ID that Amazon Comprehend assigned to the policy that you are updating. If you are creating a new policy that has no prior version, don't use this parameter. Amazon Comprehend creates the revision ID for you.</p>
    pub fn set_policy_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_revision_id = input;
        self
    }
    /// <p>The revision ID that Amazon Comprehend assigned to the policy that you are updating. If you are creating a new policy that has no prior version, don't use this parameter. Amazon Comprehend creates the revision ID for you.</p>
    pub fn get_policy_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_revision_id
    }
    /// Consumes the builder and constructs a [`PutResourcePolicyInput`](crate::operation::put_resource_policy::PutResourcePolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_resource_policy::PutResourcePolicyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_resource_policy::PutResourcePolicyInput {
            resource_arn: self.resource_arn,
            resource_policy: self.resource_policy,
            policy_revision_id: self.policy_revision_id,
        })
    }
}
