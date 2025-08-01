// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePolicyStoreInput {
    /// <p>Specifies the ID of the policy store that you want to delete.</p>
    pub policy_store_id: ::std::option::Option<::std::string::String>,
}
impl DeletePolicyStoreInput {
    /// <p>Specifies the ID of the policy store that you want to delete.</p>
    pub fn policy_store_id(&self) -> ::std::option::Option<&str> {
        self.policy_store_id.as_deref()
    }
}
impl DeletePolicyStoreInput {
    /// Creates a new builder-style object to manufacture [`DeletePolicyStoreInput`](crate::operation::delete_policy_store::DeletePolicyStoreInput).
    pub fn builder() -> crate::operation::delete_policy_store::builders::DeletePolicyStoreInputBuilder {
        crate::operation::delete_policy_store::builders::DeletePolicyStoreInputBuilder::default()
    }
}

/// A builder for [`DeletePolicyStoreInput`](crate::operation::delete_policy_store::DeletePolicyStoreInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePolicyStoreInputBuilder {
    pub(crate) policy_store_id: ::std::option::Option<::std::string::String>,
}
impl DeletePolicyStoreInputBuilder {
    /// <p>Specifies the ID of the policy store that you want to delete.</p>
    /// This field is required.
    pub fn policy_store_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_store_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ID of the policy store that you want to delete.</p>
    pub fn set_policy_store_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_store_id = input;
        self
    }
    /// <p>Specifies the ID of the policy store that you want to delete.</p>
    pub fn get_policy_store_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_store_id
    }
    /// Consumes the builder and constructs a [`DeletePolicyStoreInput`](crate::operation::delete_policy_store::DeletePolicyStoreInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_policy_store::DeletePolicyStoreInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_policy_store::DeletePolicyStoreInput {
            policy_store_id: self.policy_store_id,
        })
    }
}
