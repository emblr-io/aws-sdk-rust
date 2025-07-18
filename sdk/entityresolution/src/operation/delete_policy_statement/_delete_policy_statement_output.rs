// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePolicyStatementOutput {
    /// <p>The ARN of the resource for which the policy need to be deleted.</p>
    pub arn: ::std::string::String,
    /// <p>A unique identifier for the deleted policy.</p>
    pub token: ::std::string::String,
    /// <p>The resource-based policy.</p>
    pub policy: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeletePolicyStatementOutput {
    /// <p>The ARN of the resource for which the policy need to be deleted.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>A unique identifier for the deleted policy.</p>
    pub fn token(&self) -> &str {
        use std::ops::Deref;
        self.token.deref()
    }
    /// <p>The resource-based policy.</p>
    pub fn policy(&self) -> ::std::option::Option<&str> {
        self.policy.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeletePolicyStatementOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeletePolicyStatementOutput {
    /// Creates a new builder-style object to manufacture [`DeletePolicyStatementOutput`](crate::operation::delete_policy_statement::DeletePolicyStatementOutput).
    pub fn builder() -> crate::operation::delete_policy_statement::builders::DeletePolicyStatementOutputBuilder {
        crate::operation::delete_policy_statement::builders::DeletePolicyStatementOutputBuilder::default()
    }
}

/// A builder for [`DeletePolicyStatementOutput`](crate::operation::delete_policy_statement::DeletePolicyStatementOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePolicyStatementOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) token: ::std::option::Option<::std::string::String>,
    pub(crate) policy: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeletePolicyStatementOutputBuilder {
    /// <p>The ARN of the resource for which the policy need to be deleted.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the resource for which the policy need to be deleted.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the resource for which the policy need to be deleted.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>A unique identifier for the deleted policy.</p>
    /// This field is required.
    pub fn token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the deleted policy.</p>
    pub fn set_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.token = input;
        self
    }
    /// <p>A unique identifier for the deleted policy.</p>
    pub fn get_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.token
    }
    /// <p>The resource-based policy.</p>
    pub fn policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource-based policy.</p>
    pub fn set_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy = input;
        self
    }
    /// <p>The resource-based policy.</p>
    pub fn get_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeletePolicyStatementOutput`](crate::operation::delete_policy_statement::DeletePolicyStatementOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::operation::delete_policy_statement::builders::DeletePolicyStatementOutputBuilder::arn)
    /// - [`token`](crate::operation::delete_policy_statement::builders::DeletePolicyStatementOutputBuilder::token)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_policy_statement::DeletePolicyStatementOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_policy_statement::DeletePolicyStatementOutput {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building DeletePolicyStatementOutput",
                )
            })?,
            token: self.token.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "token",
                    "token was not specified but it is required when building DeletePolicyStatementOutput",
                )
            })?,
            policy: self.policy,
            _request_id: self._request_id,
        })
    }
}
