// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the subscription target configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SubscriptionTargetForm {
    /// <p>The form name included in the subscription target configuration.</p>
    pub form_name: ::std::string::String,
    /// <p>The content of the subscription target configuration.</p>
    pub content: ::std::string::String,
}
impl SubscriptionTargetForm {
    /// <p>The form name included in the subscription target configuration.</p>
    pub fn form_name(&self) -> &str {
        use std::ops::Deref;
        self.form_name.deref()
    }
    /// <p>The content of the subscription target configuration.</p>
    pub fn content(&self) -> &str {
        use std::ops::Deref;
        self.content.deref()
    }
}
impl SubscriptionTargetForm {
    /// Creates a new builder-style object to manufacture [`SubscriptionTargetForm`](crate::types::SubscriptionTargetForm).
    pub fn builder() -> crate::types::builders::SubscriptionTargetFormBuilder {
        crate::types::builders::SubscriptionTargetFormBuilder::default()
    }
}

/// A builder for [`SubscriptionTargetForm`](crate::types::SubscriptionTargetForm).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SubscriptionTargetFormBuilder {
    pub(crate) form_name: ::std::option::Option<::std::string::String>,
    pub(crate) content: ::std::option::Option<::std::string::String>,
}
impl SubscriptionTargetFormBuilder {
    /// <p>The form name included in the subscription target configuration.</p>
    /// This field is required.
    pub fn form_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.form_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The form name included in the subscription target configuration.</p>
    pub fn set_form_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.form_name = input;
        self
    }
    /// <p>The form name included in the subscription target configuration.</p>
    pub fn get_form_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.form_name
    }
    /// <p>The content of the subscription target configuration.</p>
    /// This field is required.
    pub fn content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The content of the subscription target configuration.</p>
    pub fn set_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content = input;
        self
    }
    /// <p>The content of the subscription target configuration.</p>
    pub fn get_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.content
    }
    /// Consumes the builder and constructs a [`SubscriptionTargetForm`](crate::types::SubscriptionTargetForm).
    /// This method will fail if any of the following fields are not set:
    /// - [`form_name`](crate::types::builders::SubscriptionTargetFormBuilder::form_name)
    /// - [`content`](crate::types::builders::SubscriptionTargetFormBuilder::content)
    pub fn build(self) -> ::std::result::Result<crate::types::SubscriptionTargetForm, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SubscriptionTargetForm {
            form_name: self.form_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "form_name",
                    "form_name was not specified but it is required when building SubscriptionTargetForm",
                )
            })?,
            content: self.content.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "content",
                    "content was not specified but it is required when building SubscriptionTargetForm",
                )
            })?,
        })
    }
}
