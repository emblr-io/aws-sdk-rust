// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEntitlementInput {
    /// <p>The name of the entitlement.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the stack with which the entitlement is associated.</p>
    pub stack_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the entitlement.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether all or selected apps are entitled.</p>
    pub app_visibility: ::std::option::Option<crate::types::AppVisibility>,
    /// <p>The attributes of the entitlement.</p>
    pub attributes: ::std::option::Option<::std::vec::Vec<crate::types::EntitlementAttribute>>,
}
impl CreateEntitlementInput {
    /// <p>The name of the entitlement.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The name of the stack with which the entitlement is associated.</p>
    pub fn stack_name(&self) -> ::std::option::Option<&str> {
        self.stack_name.as_deref()
    }
    /// <p>The description of the entitlement.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Specifies whether all or selected apps are entitled.</p>
    pub fn app_visibility(&self) -> ::std::option::Option<&crate::types::AppVisibility> {
        self.app_visibility.as_ref()
    }
    /// <p>The attributes of the entitlement.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attributes.is_none()`.
    pub fn attributes(&self) -> &[crate::types::EntitlementAttribute] {
        self.attributes.as_deref().unwrap_or_default()
    }
}
impl CreateEntitlementInput {
    /// Creates a new builder-style object to manufacture [`CreateEntitlementInput`](crate::operation::create_entitlement::CreateEntitlementInput).
    pub fn builder() -> crate::operation::create_entitlement::builders::CreateEntitlementInputBuilder {
        crate::operation::create_entitlement::builders::CreateEntitlementInputBuilder::default()
    }
}

/// A builder for [`CreateEntitlementInput`](crate::operation::create_entitlement::CreateEntitlementInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEntitlementInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) stack_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) app_visibility: ::std::option::Option<crate::types::AppVisibility>,
    pub(crate) attributes: ::std::option::Option<::std::vec::Vec<crate::types::EntitlementAttribute>>,
}
impl CreateEntitlementInputBuilder {
    /// <p>The name of the entitlement.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the entitlement.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the entitlement.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The name of the stack with which the entitlement is associated.</p>
    /// This field is required.
    pub fn stack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stack with which the entitlement is associated.</p>
    pub fn set_stack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_name = input;
        self
    }
    /// <p>The name of the stack with which the entitlement is associated.</p>
    pub fn get_stack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_name
    }
    /// <p>The description of the entitlement.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the entitlement.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the entitlement.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Specifies whether all or selected apps are entitled.</p>
    /// This field is required.
    pub fn app_visibility(mut self, input: crate::types::AppVisibility) -> Self {
        self.app_visibility = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether all or selected apps are entitled.</p>
    pub fn set_app_visibility(mut self, input: ::std::option::Option<crate::types::AppVisibility>) -> Self {
        self.app_visibility = input;
        self
    }
    /// <p>Specifies whether all or selected apps are entitled.</p>
    pub fn get_app_visibility(&self) -> &::std::option::Option<crate::types::AppVisibility> {
        &self.app_visibility
    }
    /// Appends an item to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>The attributes of the entitlement.</p>
    pub fn attributes(mut self, input: crate::types::EntitlementAttribute) -> Self {
        let mut v = self.attributes.unwrap_or_default();
        v.push(input);
        self.attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The attributes of the entitlement.</p>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EntitlementAttribute>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>The attributes of the entitlement.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EntitlementAttribute>> {
        &self.attributes
    }
    /// Consumes the builder and constructs a [`CreateEntitlementInput`](crate::operation::create_entitlement::CreateEntitlementInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_entitlement::CreateEntitlementInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_entitlement::CreateEntitlementInput {
            name: self.name,
            stack_name: self.stack_name,
            description: self.description,
            app_visibility: self.app_visibility,
            attributes: self.attributes,
        })
    }
}
