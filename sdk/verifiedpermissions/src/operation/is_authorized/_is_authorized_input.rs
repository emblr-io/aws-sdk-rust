// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IsAuthorizedInput {
    /// <p>Specifies the ID of the policy store. Policies in this policy store will be used to make an authorization decision for the input.</p>
    pub policy_store_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the principal for which the authorization decision is to be made.</p>
    pub principal: ::std::option::Option<crate::types::EntityIdentifier>,
    /// <p>Specifies the requested action to be authorized. For example, is the principal authorized to perform this action on the resource?</p>
    pub action: ::std::option::Option<crate::types::ActionIdentifier>,
    /// <p>Specifies the resource for which the authorization decision is to be made.</p>
    pub resource: ::std::option::Option<crate::types::EntityIdentifier>,
    /// <p>Specifies additional context that can be used to make more granular authorization decisions.</p>
    pub context: ::std::option::Option<crate::types::ContextDefinition>,
    /// <p>(Optional) Specifies the list of resources and principals and their associated attributes that Verified Permissions can examine when evaluating the policies. These additional entities and their attributes can be referenced and checked by conditional elements in the policies in the specified policy store.</p><note>
    /// <p>You can include only principal and resource entities in this parameter; you can't include actions. You must specify actions in the schema.</p>
    /// </note>
    pub entities: ::std::option::Option<crate::types::EntitiesDefinition>,
}
impl IsAuthorizedInput {
    /// <p>Specifies the ID of the policy store. Policies in this policy store will be used to make an authorization decision for the input.</p>
    pub fn policy_store_id(&self) -> ::std::option::Option<&str> {
        self.policy_store_id.as_deref()
    }
    /// <p>Specifies the principal for which the authorization decision is to be made.</p>
    pub fn principal(&self) -> ::std::option::Option<&crate::types::EntityIdentifier> {
        self.principal.as_ref()
    }
    /// <p>Specifies the requested action to be authorized. For example, is the principal authorized to perform this action on the resource?</p>
    pub fn action(&self) -> ::std::option::Option<&crate::types::ActionIdentifier> {
        self.action.as_ref()
    }
    /// <p>Specifies the resource for which the authorization decision is to be made.</p>
    pub fn resource(&self) -> ::std::option::Option<&crate::types::EntityIdentifier> {
        self.resource.as_ref()
    }
    /// <p>Specifies additional context that can be used to make more granular authorization decisions.</p>
    pub fn context(&self) -> ::std::option::Option<&crate::types::ContextDefinition> {
        self.context.as_ref()
    }
    /// <p>(Optional) Specifies the list of resources and principals and their associated attributes that Verified Permissions can examine when evaluating the policies. These additional entities and their attributes can be referenced and checked by conditional elements in the policies in the specified policy store.</p><note>
    /// <p>You can include only principal and resource entities in this parameter; you can't include actions. You must specify actions in the schema.</p>
    /// </note>
    pub fn entities(&self) -> ::std::option::Option<&crate::types::EntitiesDefinition> {
        self.entities.as_ref()
    }
}
impl IsAuthorizedInput {
    /// Creates a new builder-style object to manufacture [`IsAuthorizedInput`](crate::operation::is_authorized::IsAuthorizedInput).
    pub fn builder() -> crate::operation::is_authorized::builders::IsAuthorizedInputBuilder {
        crate::operation::is_authorized::builders::IsAuthorizedInputBuilder::default()
    }
}

/// A builder for [`IsAuthorizedInput`](crate::operation::is_authorized::IsAuthorizedInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IsAuthorizedInputBuilder {
    pub(crate) policy_store_id: ::std::option::Option<::std::string::String>,
    pub(crate) principal: ::std::option::Option<crate::types::EntityIdentifier>,
    pub(crate) action: ::std::option::Option<crate::types::ActionIdentifier>,
    pub(crate) resource: ::std::option::Option<crate::types::EntityIdentifier>,
    pub(crate) context: ::std::option::Option<crate::types::ContextDefinition>,
    pub(crate) entities: ::std::option::Option<crate::types::EntitiesDefinition>,
}
impl IsAuthorizedInputBuilder {
    /// <p>Specifies the ID of the policy store. Policies in this policy store will be used to make an authorization decision for the input.</p>
    /// This field is required.
    pub fn policy_store_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_store_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ID of the policy store. Policies in this policy store will be used to make an authorization decision for the input.</p>
    pub fn set_policy_store_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_store_id = input;
        self
    }
    /// <p>Specifies the ID of the policy store. Policies in this policy store will be used to make an authorization decision for the input.</p>
    pub fn get_policy_store_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_store_id
    }
    /// <p>Specifies the principal for which the authorization decision is to be made.</p>
    pub fn principal(mut self, input: crate::types::EntityIdentifier) -> Self {
        self.principal = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the principal for which the authorization decision is to be made.</p>
    pub fn set_principal(mut self, input: ::std::option::Option<crate::types::EntityIdentifier>) -> Self {
        self.principal = input;
        self
    }
    /// <p>Specifies the principal for which the authorization decision is to be made.</p>
    pub fn get_principal(&self) -> &::std::option::Option<crate::types::EntityIdentifier> {
        &self.principal
    }
    /// <p>Specifies the requested action to be authorized. For example, is the principal authorized to perform this action on the resource?</p>
    pub fn action(mut self, input: crate::types::ActionIdentifier) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the requested action to be authorized. For example, is the principal authorized to perform this action on the resource?</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::ActionIdentifier>) -> Self {
        self.action = input;
        self
    }
    /// <p>Specifies the requested action to be authorized. For example, is the principal authorized to perform this action on the resource?</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::ActionIdentifier> {
        &self.action
    }
    /// <p>Specifies the resource for which the authorization decision is to be made.</p>
    pub fn resource(mut self, input: crate::types::EntityIdentifier) -> Self {
        self.resource = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the resource for which the authorization decision is to be made.</p>
    pub fn set_resource(mut self, input: ::std::option::Option<crate::types::EntityIdentifier>) -> Self {
        self.resource = input;
        self
    }
    /// <p>Specifies the resource for which the authorization decision is to be made.</p>
    pub fn get_resource(&self) -> &::std::option::Option<crate::types::EntityIdentifier> {
        &self.resource
    }
    /// <p>Specifies additional context that can be used to make more granular authorization decisions.</p>
    pub fn context(mut self, input: crate::types::ContextDefinition) -> Self {
        self.context = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies additional context that can be used to make more granular authorization decisions.</p>
    pub fn set_context(mut self, input: ::std::option::Option<crate::types::ContextDefinition>) -> Self {
        self.context = input;
        self
    }
    /// <p>Specifies additional context that can be used to make more granular authorization decisions.</p>
    pub fn get_context(&self) -> &::std::option::Option<crate::types::ContextDefinition> {
        &self.context
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
    /// Consumes the builder and constructs a [`IsAuthorizedInput`](crate::operation::is_authorized::IsAuthorizedInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::is_authorized::IsAuthorizedInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::is_authorized::IsAuthorizedInput {
            policy_store_id: self.policy_store_id,
            principal: self.principal,
            action: self.action,
            resource: self.resource,
            context: self.context,
            entities: self.entities,
        })
    }
}
