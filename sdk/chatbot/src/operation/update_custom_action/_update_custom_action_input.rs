// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateCustomActionInput {
    /// <p>The fully defined Amazon Resource Name (ARN) of the custom action.</p>
    pub custom_action_arn: ::std::option::Option<::std::string::String>,
    /// <p>The definition of the command to run when invoked as an alias or as an action button.</p>
    pub definition: ::std::option::Option<crate::types::CustomActionDefinition>,
    /// <p>The name used to invoke this action in the chat channel. For example, <code>@aws run my-alias</code>.</p>
    pub alias_name: ::std::option::Option<::std::string::String>,
    /// <p>Defines when this custom action button should be attached to a notification.</p>
    pub attachments: ::std::option::Option<::std::vec::Vec<crate::types::CustomActionAttachment>>,
}
impl UpdateCustomActionInput {
    /// <p>The fully defined Amazon Resource Name (ARN) of the custom action.</p>
    pub fn custom_action_arn(&self) -> ::std::option::Option<&str> {
        self.custom_action_arn.as_deref()
    }
    /// <p>The definition of the command to run when invoked as an alias or as an action button.</p>
    pub fn definition(&self) -> ::std::option::Option<&crate::types::CustomActionDefinition> {
        self.definition.as_ref()
    }
    /// <p>The name used to invoke this action in the chat channel. For example, <code>@aws run my-alias</code>.</p>
    pub fn alias_name(&self) -> ::std::option::Option<&str> {
        self.alias_name.as_deref()
    }
    /// <p>Defines when this custom action button should be attached to a notification.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attachments.is_none()`.
    pub fn attachments(&self) -> &[crate::types::CustomActionAttachment] {
        self.attachments.as_deref().unwrap_or_default()
    }
}
impl UpdateCustomActionInput {
    /// Creates a new builder-style object to manufacture [`UpdateCustomActionInput`](crate::operation::update_custom_action::UpdateCustomActionInput).
    pub fn builder() -> crate::operation::update_custom_action::builders::UpdateCustomActionInputBuilder {
        crate::operation::update_custom_action::builders::UpdateCustomActionInputBuilder::default()
    }
}

/// A builder for [`UpdateCustomActionInput`](crate::operation::update_custom_action::UpdateCustomActionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateCustomActionInputBuilder {
    pub(crate) custom_action_arn: ::std::option::Option<::std::string::String>,
    pub(crate) definition: ::std::option::Option<crate::types::CustomActionDefinition>,
    pub(crate) alias_name: ::std::option::Option<::std::string::String>,
    pub(crate) attachments: ::std::option::Option<::std::vec::Vec<crate::types::CustomActionAttachment>>,
}
impl UpdateCustomActionInputBuilder {
    /// <p>The fully defined Amazon Resource Name (ARN) of the custom action.</p>
    /// This field is required.
    pub fn custom_action_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_action_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The fully defined Amazon Resource Name (ARN) of the custom action.</p>
    pub fn set_custom_action_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_action_arn = input;
        self
    }
    /// <p>The fully defined Amazon Resource Name (ARN) of the custom action.</p>
    pub fn get_custom_action_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_action_arn
    }
    /// <p>The definition of the command to run when invoked as an alias or as an action button.</p>
    /// This field is required.
    pub fn definition(mut self, input: crate::types::CustomActionDefinition) -> Self {
        self.definition = ::std::option::Option::Some(input);
        self
    }
    /// <p>The definition of the command to run when invoked as an alias or as an action button.</p>
    pub fn set_definition(mut self, input: ::std::option::Option<crate::types::CustomActionDefinition>) -> Self {
        self.definition = input;
        self
    }
    /// <p>The definition of the command to run when invoked as an alias or as an action button.</p>
    pub fn get_definition(&self) -> &::std::option::Option<crate::types::CustomActionDefinition> {
        &self.definition
    }
    /// <p>The name used to invoke this action in the chat channel. For example, <code>@aws run my-alias</code>.</p>
    pub fn alias_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name used to invoke this action in the chat channel. For example, <code>@aws run my-alias</code>.</p>
    pub fn set_alias_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias_name = input;
        self
    }
    /// <p>The name used to invoke this action in the chat channel. For example, <code>@aws run my-alias</code>.</p>
    pub fn get_alias_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias_name
    }
    /// Appends an item to `attachments`.
    ///
    /// To override the contents of this collection use [`set_attachments`](Self::set_attachments).
    ///
    /// <p>Defines when this custom action button should be attached to a notification.</p>
    pub fn attachments(mut self, input: crate::types::CustomActionAttachment) -> Self {
        let mut v = self.attachments.unwrap_or_default();
        v.push(input);
        self.attachments = ::std::option::Option::Some(v);
        self
    }
    /// <p>Defines when this custom action button should be attached to a notification.</p>
    pub fn set_attachments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CustomActionAttachment>>) -> Self {
        self.attachments = input;
        self
    }
    /// <p>Defines when this custom action button should be attached to a notification.</p>
    pub fn get_attachments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CustomActionAttachment>> {
        &self.attachments
    }
    /// Consumes the builder and constructs a [`UpdateCustomActionInput`](crate::operation::update_custom_action::UpdateCustomActionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_custom_action::UpdateCustomActionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_custom_action::UpdateCustomActionInput {
            custom_action_arn: self.custom_action_arn,
            definition: self.definition,
            alias_name: self.alias_name,
            attachments: self.attachments,
        })
    }
}
