// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a policy that you include in a <code>BatchGetPolicy</code> API request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetPolicyInputItem {
    /// <p>The identifier of the policy store where the policy you want information about is stored.</p>
    pub policy_store_id: ::std::string::String,
    /// <p>The identifier of the policy you want information about.</p>
    pub policy_id: ::std::string::String,
}
impl BatchGetPolicyInputItem {
    /// <p>The identifier of the policy store where the policy you want information about is stored.</p>
    pub fn policy_store_id(&self) -> &str {
        use std::ops::Deref;
        self.policy_store_id.deref()
    }
    /// <p>The identifier of the policy you want information about.</p>
    pub fn policy_id(&self) -> &str {
        use std::ops::Deref;
        self.policy_id.deref()
    }
}
impl BatchGetPolicyInputItem {
    /// Creates a new builder-style object to manufacture [`BatchGetPolicyInputItem`](crate::types::BatchGetPolicyInputItem).
    pub fn builder() -> crate::types::builders::BatchGetPolicyInputItemBuilder {
        crate::types::builders::BatchGetPolicyInputItemBuilder::default()
    }
}

/// A builder for [`BatchGetPolicyInputItem`](crate::types::BatchGetPolicyInputItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetPolicyInputItemBuilder {
    pub(crate) policy_store_id: ::std::option::Option<::std::string::String>,
    pub(crate) policy_id: ::std::option::Option<::std::string::String>,
}
impl BatchGetPolicyInputItemBuilder {
    /// <p>The identifier of the policy store where the policy you want information about is stored.</p>
    /// This field is required.
    pub fn policy_store_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_store_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the policy store where the policy you want information about is stored.</p>
    pub fn set_policy_store_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_store_id = input;
        self
    }
    /// <p>The identifier of the policy store where the policy you want information about is stored.</p>
    pub fn get_policy_store_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_store_id
    }
    /// <p>The identifier of the policy you want information about.</p>
    /// This field is required.
    pub fn policy_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the policy you want information about.</p>
    pub fn set_policy_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_id = input;
        self
    }
    /// <p>The identifier of the policy you want information about.</p>
    pub fn get_policy_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_id
    }
    /// Consumes the builder and constructs a [`BatchGetPolicyInputItem`](crate::types::BatchGetPolicyInputItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`policy_store_id`](crate::types::builders::BatchGetPolicyInputItemBuilder::policy_store_id)
    /// - [`policy_id`](crate::types::builders::BatchGetPolicyInputItemBuilder::policy_id)
    pub fn build(self) -> ::std::result::Result<crate::types::BatchGetPolicyInputItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BatchGetPolicyInputItem {
            policy_store_id: self.policy_store_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "policy_store_id",
                    "policy_store_id was not specified but it is required when building BatchGetPolicyInputItem",
                )
            })?,
            policy_id: self.policy_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "policy_id",
                    "policy_id was not specified but it is required when building BatchGetPolicyInputItem",
                )
            })?,
        })
    }
}
