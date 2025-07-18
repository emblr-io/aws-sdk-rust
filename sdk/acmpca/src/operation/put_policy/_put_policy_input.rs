// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutPolicyInput {
    /// <p>The Amazon Resource Number (ARN) of the private CA to associate with the policy. The ARN of the CA can be found by calling the <a href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html">ListCertificateAuthorities</a> action.</p>
    /// <p></p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The path and file name of a JSON-formatted IAM policy to attach to the specified private CA resource. If this policy does not contain all required statements or if it includes any statement that is not allowed, the <code>PutPolicy</code> action returns an <code>InvalidPolicyException</code>. For information about IAM policy and statement structure, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policies-json">Overview of JSON Policies</a>.</p>
    pub policy: ::std::option::Option<::std::string::String>,
}
impl PutPolicyInput {
    /// <p>The Amazon Resource Number (ARN) of the private CA to associate with the policy. The ARN of the CA can be found by calling the <a href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html">ListCertificateAuthorities</a> action.</p>
    /// <p></p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The path and file name of a JSON-formatted IAM policy to attach to the specified private CA resource. If this policy does not contain all required statements or if it includes any statement that is not allowed, the <code>PutPolicy</code> action returns an <code>InvalidPolicyException</code>. For information about IAM policy and statement structure, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policies-json">Overview of JSON Policies</a>.</p>
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
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) policy: ::std::option::Option<::std::string::String>,
}
impl PutPolicyInputBuilder {
    /// <p>The Amazon Resource Number (ARN) of the private CA to associate with the policy. The ARN of the CA can be found by calling the <a href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html">ListCertificateAuthorities</a> action.</p>
    /// <p></p>
    /// This field is required.
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the private CA to associate with the policy. The ARN of the CA can be found by calling the <a href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html">ListCertificateAuthorities</a> action.</p>
    /// <p></p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the private CA to associate with the policy. The ARN of the CA can be found by calling the <a href="https://docs.aws.amazon.com/privateca/latest/APIReference/API_ListCertificateAuthorities.html">ListCertificateAuthorities</a> action.</p>
    /// <p></p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The path and file name of a JSON-formatted IAM policy to attach to the specified private CA resource. If this policy does not contain all required statements or if it includes any statement that is not allowed, the <code>PutPolicy</code> action returns an <code>InvalidPolicyException</code>. For information about IAM policy and statement structure, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policies-json">Overview of JSON Policies</a>.</p>
    /// This field is required.
    pub fn policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path and file name of a JSON-formatted IAM policy to attach to the specified private CA resource. If this policy does not contain all required statements or if it includes any statement that is not allowed, the <code>PutPolicy</code> action returns an <code>InvalidPolicyException</code>. For information about IAM policy and statement structure, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policies-json">Overview of JSON Policies</a>.</p>
    pub fn set_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy = input;
        self
    }
    /// <p>The path and file name of a JSON-formatted IAM policy to attach to the specified private CA resource. If this policy does not contain all required statements or if it includes any statement that is not allowed, the <code>PutPolicy</code> action returns an <code>InvalidPolicyException</code>. For information about IAM policy and statement structure, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#access_policies-json">Overview of JSON Policies</a>.</p>
    pub fn get_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy
    }
    /// Consumes the builder and constructs a [`PutPolicyInput`](crate::operation::put_policy::PutPolicyInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::put_policy::PutPolicyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_policy::PutPolicyInput {
            resource_arn: self.resource_arn,
            policy: self.policy,
        })
    }
}
