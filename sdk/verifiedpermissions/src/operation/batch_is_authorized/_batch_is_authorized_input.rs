// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchIsAuthorizedInput {
    /// <p>Specifies the ID of the policy store. Policies in this policy store will be used to make the authorization decisions for the input.</p>
    pub policy_store_id: ::std::option::Option<::std::string::String>,
    /// <p>(Optional) Specifies the list of resources and principals and their associated attributes that Verified Permissions can examine when evaluating the policies. These additional entities and their attributes can be referenced and checked by conditional elements in the policies in the specified policy store.</p><note>
    /// <p>You can include only principal and resource entities in this parameter; you can't include actions. You must specify actions in the schema.</p>
    /// </note>
    pub entities: ::std::option::Option<crate::types::EntitiesDefinition>,
    /// <p>An array of up to 30 requests that you want Verified Permissions to evaluate.</p>
    pub requests: ::std::option::Option<::std::vec::Vec<crate::types::BatchIsAuthorizedInputItem>>,
}
impl BatchIsAuthorizedInput {
    /// <p>Specifies the ID of the policy store. Policies in this policy store will be used to make the authorization decisions for the input.</p>
    pub fn policy_store_id(&self) -> ::std::option::Option<&str> {
        self.policy_store_id.as_deref()
    }
    /// <p>(Optional) Specifies the list of resources and principals and their associated attributes that Verified Permissions can examine when evaluating the policies. These additional entities and their attributes can be referenced and checked by conditional elements in the policies in the specified policy store.</p><note>
    /// <p>You can include only principal and resource entities in this parameter; you can't include actions. You must specify actions in the schema.</p>
    /// </note>
    pub fn entities(&self) -> ::std::option::Option<&crate::types::EntitiesDefinition> {
        self.entities.as_ref()
    }
    /// <p>An array of up to 30 requests that you want Verified Permissions to evaluate.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.requests.is_none()`.
    pub fn requests(&self) -> &[crate::types::BatchIsAuthorizedInputItem] {
        self.requests.as_deref().unwrap_or_default()
    }
}
impl BatchIsAuthorizedInput {
    /// Creates a new builder-style object to manufacture [`BatchIsAuthorizedInput`](crate::operation::batch_is_authorized::BatchIsAuthorizedInput).
    pub fn builder() -> crate::operation::batch_is_authorized::builders::BatchIsAuthorizedInputBuilder {
        crate::operation::batch_is_authorized::builders::BatchIsAuthorizedInputBuilder::default()
    }
}

/// A builder for [`BatchIsAuthorizedInput`](crate::operation::batch_is_authorized::BatchIsAuthorizedInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchIsAuthorizedInputBuilder {
    pub(crate) policy_store_id: ::std::option::Option<::std::string::String>,
    pub(crate) entities: ::std::option::Option<crate::types::EntitiesDefinition>,
    pub(crate) requests: ::std::option::Option<::std::vec::Vec<crate::types::BatchIsAuthorizedInputItem>>,
}
impl BatchIsAuthorizedInputBuilder {
    /// <p>Specifies the ID of the policy store. Policies in this policy store will be used to make the authorization decisions for the input.</p>
    /// This field is required.
    pub fn policy_store_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_store_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ID of the policy store. Policies in this policy store will be used to make the authorization decisions for the input.</p>
    pub fn set_policy_store_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_store_id = input;
        self
    }
    /// <p>Specifies the ID of the policy store. Policies in this policy store will be used to make the authorization decisions for the input.</p>
    pub fn get_policy_store_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_store_id
    }
    /// <p>(Optional) Specifies the list of resources and principals and their associated attributes that Verified Permissions can examine when evaluating the policies. These additional entities and their attributes can be referenced and checked by conditional elements in the policies in the specified policy store.</p><note>
    /// <p>You can include only principal and resource entities in this parameter; you can't include actions. You must specify actions in the schema.</p>
    /// </note>
    pub fn entities(mut self, input: crate::types::EntitiesDefinition) -> Self {
        self.entities = ::std::option::Option::Some(input);
        self
    }
    /// <p>(Optional) Specifies the list of resources and principals and their associated attributes that Verified Permissions can examine when evaluating the policies. These additional entities and their attributes can be referenced and checked by conditional elements in the policies in the specified policy store.</p><note>
    /// <p>You can include only principal and resource entities in this parameter; you can't include actions. You must specify actions in the schema.</p>
    /// </note>
    pub fn set_entities(mut self, input: ::std::option::Option<crate::types::EntitiesDefinition>) -> Self {
        self.entities = input;
        self
    }
    /// <p>(Optional) Specifies the list of resources and principals and their associated attributes that Verified Permissions can examine when evaluating the policies. These additional entities and their attributes can be referenced and checked by conditional elements in the policies in the specified policy store.</p><note>
    /// <p>You can include only principal and resource entities in this parameter; you can't include actions. You must specify actions in the schema.</p>
    /// </note>
    pub fn get_entities(&self) -> &::std::option::Option<crate::types::EntitiesDefinition> {
        &self.entities
    }
    /// Appends an item to `requests`.
    ///
    /// To override the contents of this collection use [`set_requests`](Self::set_requests).
    ///
    /// <p>An array of up to 30 requests that you want Verified Permissions to evaluate.</p>
    pub fn requests(mut self, input: crate::types::BatchIsAuthorizedInputItem) -> Self {
        let mut v = self.requests.unwrap_or_default();
        v.push(input);
        self.requests = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of up to 30 requests that you want Verified Permissions to evaluate.</p>
    pub fn set_requests(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BatchIsAuthorizedInputItem>>) -> Self {
        self.requests = input;
        self
    }
    /// <p>An array of up to 30 requests that you want Verified Permissions to evaluate.</p>
    pub fn get_requests(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BatchIsAuthorizedInputItem>> {
        &self.requests
    }
    /// Consumes the builder and constructs a [`BatchIsAuthorizedInput`](crate::operation::batch_is_authorized::BatchIsAuthorizedInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::batch_is_authorized::BatchIsAuthorizedInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::batch_is_authorized::BatchIsAuthorizedInput {
            policy_store_id: self.policy_store_id,
            entities: self.entities,
            requests: self.requests,
        })
    }
}
