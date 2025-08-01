// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetKeyPolicyInput {
    /// <p>Gets the key policy for the specified KMS key.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    pub key_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the name of the key policy. If no policy name is specified, the default value is <code>default</code>. The only valid name is <code>default</code>. To get the names of key policies, use <code>ListKeyPolicies</code>.</p>
    pub policy_name: ::std::option::Option<::std::string::String>,
}
impl GetKeyPolicyInput {
    /// <p>Gets the key policy for the specified KMS key.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    pub fn key_id(&self) -> ::std::option::Option<&str> {
        self.key_id.as_deref()
    }
    /// <p>Specifies the name of the key policy. If no policy name is specified, the default value is <code>default</code>. The only valid name is <code>default</code>. To get the names of key policies, use <code>ListKeyPolicies</code>.</p>
    pub fn policy_name(&self) -> ::std::option::Option<&str> {
        self.policy_name.as_deref()
    }
}
impl GetKeyPolicyInput {
    /// Creates a new builder-style object to manufacture [`GetKeyPolicyInput`](crate::operation::get_key_policy::GetKeyPolicyInput).
    pub fn builder() -> crate::operation::get_key_policy::builders::GetKeyPolicyInputBuilder {
        crate::operation::get_key_policy::builders::GetKeyPolicyInputBuilder::default()
    }
}

/// A builder for [`GetKeyPolicyInput`](crate::operation::get_key_policy::GetKeyPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetKeyPolicyInputBuilder {
    pub(crate) key_id: ::std::option::Option<::std::string::String>,
    pub(crate) policy_name: ::std::option::Option<::std::string::String>,
}
impl GetKeyPolicyInputBuilder {
    /// <p>Gets the key policy for the specified KMS key.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    /// This field is required.
    pub fn key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Gets the key policy for the specified KMS key.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    pub fn set_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_id = input;
        self
    }
    /// <p>Gets the key policy for the specified KMS key.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    pub fn get_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_id
    }
    /// <p>Specifies the name of the key policy. If no policy name is specified, the default value is <code>default</code>. The only valid name is <code>default</code>. To get the names of key policies, use <code>ListKeyPolicies</code>.</p>
    pub fn policy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the name of the key policy. If no policy name is specified, the default value is <code>default</code>. The only valid name is <code>default</code>. To get the names of key policies, use <code>ListKeyPolicies</code>.</p>
    pub fn set_policy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_name = input;
        self
    }
    /// <p>Specifies the name of the key policy. If no policy name is specified, the default value is <code>default</code>. The only valid name is <code>default</code>. To get the names of key policies, use <code>ListKeyPolicies</code>.</p>
    pub fn get_policy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_name
    }
    /// Consumes the builder and constructs a [`GetKeyPolicyInput`](crate::operation::get_key_policy::GetKeyPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_key_policy::GetKeyPolicyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_key_policy::GetKeyPolicyInput {
            key_id: self.key_id,
            policy_name: self.policy_name,
        })
    }
}
