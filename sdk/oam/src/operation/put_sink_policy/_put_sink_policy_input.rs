// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutSinkPolicyInput {
    /// <p>The ARN of the sink to attach this policy to.</p>
    pub sink_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The JSON policy to use. If you are updating an existing policy, the entire existing policy is replaced by what you specify here.</p>
    /// <p>The policy must be in JSON string format with quotation marks escaped and no newlines.</p>
    /// <p>For examples of different types of policies, see the <b>Examples</b> section on this page.</p>
    pub policy: ::std::option::Option<::std::string::String>,
}
impl PutSinkPolicyInput {
    /// <p>The ARN of the sink to attach this policy to.</p>
    pub fn sink_identifier(&self) -> ::std::option::Option<&str> {
        self.sink_identifier.as_deref()
    }
    /// <p>The JSON policy to use. If you are updating an existing policy, the entire existing policy is replaced by what you specify here.</p>
    /// <p>The policy must be in JSON string format with quotation marks escaped and no newlines.</p>
    /// <p>For examples of different types of policies, see the <b>Examples</b> section on this page.</p>
    pub fn policy(&self) -> ::std::option::Option<&str> {
        self.policy.as_deref()
    }
}
impl PutSinkPolicyInput {
    /// Creates a new builder-style object to manufacture [`PutSinkPolicyInput`](crate::operation::put_sink_policy::PutSinkPolicyInput).
    pub fn builder() -> crate::operation::put_sink_policy::builders::PutSinkPolicyInputBuilder {
        crate::operation::put_sink_policy::builders::PutSinkPolicyInputBuilder::default()
    }
}

/// A builder for [`PutSinkPolicyInput`](crate::operation::put_sink_policy::PutSinkPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutSinkPolicyInputBuilder {
    pub(crate) sink_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) policy: ::std::option::Option<::std::string::String>,
}
impl PutSinkPolicyInputBuilder {
    /// <p>The ARN of the sink to attach this policy to.</p>
    /// This field is required.
    pub fn sink_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sink_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the sink to attach this policy to.</p>
    pub fn set_sink_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sink_identifier = input;
        self
    }
    /// <p>The ARN of the sink to attach this policy to.</p>
    pub fn get_sink_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.sink_identifier
    }
    /// <p>The JSON policy to use. If you are updating an existing policy, the entire existing policy is replaced by what you specify here.</p>
    /// <p>The policy must be in JSON string format with quotation marks escaped and no newlines.</p>
    /// <p>For examples of different types of policies, see the <b>Examples</b> section on this page.</p>
    /// This field is required.
    pub fn policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The JSON policy to use. If you are updating an existing policy, the entire existing policy is replaced by what you specify here.</p>
    /// <p>The policy must be in JSON string format with quotation marks escaped and no newlines.</p>
    /// <p>For examples of different types of policies, see the <b>Examples</b> section on this page.</p>
    pub fn set_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy = input;
        self
    }
    /// <p>The JSON policy to use. If you are updating an existing policy, the entire existing policy is replaced by what you specify here.</p>
    /// <p>The policy must be in JSON string format with quotation marks escaped and no newlines.</p>
    /// <p>For examples of different types of policies, see the <b>Examples</b> section on this page.</p>
    pub fn get_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy
    }
    /// Consumes the builder and constructs a [`PutSinkPolicyInput`](crate::operation::put_sink_policy::PutSinkPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_sink_policy::PutSinkPolicyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_sink_policy::PutSinkPolicyInput {
            sink_identifier: self.sink_identifier,
            policy: self.policy,
        })
    }
}
