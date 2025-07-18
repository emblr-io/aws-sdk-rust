// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutPolicyInput {
    /// <p>The Amazon Resource Name (ARN) of the resource for which the policy needs to be updated.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for the current revision of the policy.</p>
    pub token: ::std::option::Option<::std::string::String>,
    /// <p>The resource-based policy.</p><important>
    /// <p>If you set the value of the <code>effect</code> parameter in the <code>policy</code> to <code>Deny</code> for the <code>PutPolicy</code> operation, you must also set the value of the <code>effect</code> parameter to <code>Deny</code> for the <code>AddPolicyStatement</code> operation.</p>
    /// </important>
    pub policy: ::std::option::Option<::std::string::String>,
}
impl PutPolicyInput {
    /// <p>The Amazon Resource Name (ARN) of the resource for which the policy needs to be updated.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>A unique identifier for the current revision of the policy.</p>
    pub fn token(&self) -> ::std::option::Option<&str> {
        self.token.as_deref()
    }
    /// <p>The resource-based policy.</p><important>
    /// <p>If you set the value of the <code>effect</code> parameter in the <code>policy</code> to <code>Deny</code> for the <code>PutPolicy</code> operation, you must also set the value of the <code>effect</code> parameter to <code>Deny</code> for the <code>AddPolicyStatement</code> operation.</p>
    /// </important>
    pub fn policy(&self) -> ::std::option::Option<&str> {
        self.policy.as_deref()
    }
}
impl PutPolicyInput {
    /// Creates a new builder-style object to manufacture [`PutPolicyInput`](crate::operation::put_policy::PutPolicyInput).
    pub fn builder() -> crate::operation::put_policy::builders::PutPolicyInputBuilder {
        crate::operation::put_policy::builders::PutPolicyInputBuilder::default()
    }
}

/// A builder for [`PutPolicyInput`](crate::operation::put_policy::PutPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutPolicyInputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) token: ::std::option::Option<::std::string::String>,
    pub(crate) policy: ::std::option::Option<::std::string::String>,
}
impl PutPolicyInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the resource for which the policy needs to be updated.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource for which the policy needs to be updated.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource for which the policy needs to be updated.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>A unique identifier for the current revision of the policy.</p>
    pub fn token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the current revision of the policy.</p>
    pub fn set_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.token = input;
        self
    }
    /// <p>A unique identifier for the current revision of the policy.</p>
    pub fn get_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.token
    }
    /// <p>The resource-based policy.</p><important>
    /// <p>If you set the value of the <code>effect</code> parameter in the <code>policy</code> to <code>Deny</code> for the <code>PutPolicy</code> operation, you must also set the value of the <code>effect</code> parameter to <code>Deny</code> for the <code>AddPolicyStatement</code> operation.</p>
    /// </important>
    /// This field is required.
    pub fn policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource-based policy.</p><important>
    /// <p>If you set the value of the <code>effect</code> parameter in the <code>policy</code> to <code>Deny</code> for the <code>PutPolicy</code> operation, you must also set the value of the <code>effect</code> parameter to <code>Deny</code> for the <code>AddPolicyStatement</code> operation.</p>
    /// </important>
    pub fn set_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy = input;
        self
    }
    /// <p>The resource-based policy.</p><important>
    /// <p>If you set the value of the <code>effect</code> parameter in the <code>policy</code> to <code>Deny</code> for the <code>PutPolicy</code> operation, you must also set the value of the <code>effect</code> parameter to <code>Deny</code> for the <code>AddPolicyStatement</code> operation.</p>
    /// </important>
    pub fn get_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy
    }
    /// Consumes the builder and constructs a [`PutPolicyInput`](crate::operation::put_policy::PutPolicyInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::put_policy::PutPolicyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_policy::PutPolicyInput {
            arn: self.arn,
            token: self.token,
            policy: self.policy,
        })
    }
}
