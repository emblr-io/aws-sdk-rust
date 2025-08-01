// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The input for the DetachPrincipalPolicy operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DetachPrincipalPolicyInput {
    /// <p>The name of the policy to detach.</p>
    pub policy_name: ::std::option::Option<::std::string::String>,
    /// <p>The principal.</p>
    /// <p>Valid principals are CertificateArn (arn:aws:iot:<i>region</i>:<i>accountId</i>:cert/<i>certificateId</i>), thingGroupArn (arn:aws:iot:<i>region</i>:<i>accountId</i>:thinggroup/<i>groupName</i>) and CognitoId (<i>region</i>:<i>id</i>).</p>
    pub principal: ::std::option::Option<::std::string::String>,
}
impl DetachPrincipalPolicyInput {
    /// <p>The name of the policy to detach.</p>
    pub fn policy_name(&self) -> ::std::option::Option<&str> {
        self.policy_name.as_deref()
    }
    /// <p>The principal.</p>
    /// <p>Valid principals are CertificateArn (arn:aws:iot:<i>region</i>:<i>accountId</i>:cert/<i>certificateId</i>), thingGroupArn (arn:aws:iot:<i>region</i>:<i>accountId</i>:thinggroup/<i>groupName</i>) and CognitoId (<i>region</i>:<i>id</i>).</p>
    pub fn principal(&self) -> ::std::option::Option<&str> {
        self.principal.as_deref()
    }
}
impl DetachPrincipalPolicyInput {
    /// Creates a new builder-style object to manufacture [`DetachPrincipalPolicyInput`](crate::operation::detach_principal_policy::DetachPrincipalPolicyInput).
    pub fn builder() -> crate::operation::detach_principal_policy::builders::DetachPrincipalPolicyInputBuilder {
        crate::operation::detach_principal_policy::builders::DetachPrincipalPolicyInputBuilder::default()
    }
}

/// A builder for [`DetachPrincipalPolicyInput`](crate::operation::detach_principal_policy::DetachPrincipalPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetachPrincipalPolicyInputBuilder {
    pub(crate) policy_name: ::std::option::Option<::std::string::String>,
    pub(crate) principal: ::std::option::Option<::std::string::String>,
}
impl DetachPrincipalPolicyInputBuilder {
    /// <p>The name of the policy to detach.</p>
    /// This field is required.
    pub fn policy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the policy to detach.</p>
    pub fn set_policy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_name = input;
        self
    }
    /// <p>The name of the policy to detach.</p>
    pub fn get_policy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_name
    }
    /// <p>The principal.</p>
    /// <p>Valid principals are CertificateArn (arn:aws:iot:<i>region</i>:<i>accountId</i>:cert/<i>certificateId</i>), thingGroupArn (arn:aws:iot:<i>region</i>:<i>accountId</i>:thinggroup/<i>groupName</i>) and CognitoId (<i>region</i>:<i>id</i>).</p>
    /// This field is required.
    pub fn principal(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The principal.</p>
    /// <p>Valid principals are CertificateArn (arn:aws:iot:<i>region</i>:<i>accountId</i>:cert/<i>certificateId</i>), thingGroupArn (arn:aws:iot:<i>region</i>:<i>accountId</i>:thinggroup/<i>groupName</i>) and CognitoId (<i>region</i>:<i>id</i>).</p>
    pub fn set_principal(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal = input;
        self
    }
    /// <p>The principal.</p>
    /// <p>Valid principals are CertificateArn (arn:aws:iot:<i>region</i>:<i>accountId</i>:cert/<i>certificateId</i>), thingGroupArn (arn:aws:iot:<i>region</i>:<i>accountId</i>:thinggroup/<i>groupName</i>) and CognitoId (<i>region</i>:<i>id</i>).</p>
    pub fn get_principal(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal
    }
    /// Consumes the builder and constructs a [`DetachPrincipalPolicyInput`](crate::operation::detach_principal_policy::DetachPrincipalPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::detach_principal_policy::DetachPrincipalPolicyInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::detach_principal_policy::DetachPrincipalPolicyInput {
            policy_name: self.policy_name,
            principal: self.principal,
        })
    }
}
