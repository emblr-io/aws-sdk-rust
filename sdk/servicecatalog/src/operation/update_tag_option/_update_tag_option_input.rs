// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateTagOptionInput {
    /// <p>The TagOption identifier.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The updated value.</p>
    pub value: ::std::option::Option<::std::string::String>,
    /// <p>The updated active state.</p>
    pub active: ::std::option::Option<bool>,
}
impl UpdateTagOptionInput {
    /// <p>The TagOption identifier.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The updated value.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
    /// <p>The updated active state.</p>
    pub fn active(&self) -> ::std::option::Option<bool> {
        self.active
    }
}
impl UpdateTagOptionInput {
    /// Creates a new builder-style object to manufacture [`UpdateTagOptionInput`](crate::operation::update_tag_option::UpdateTagOptionInput).
    pub fn builder() -> crate::operation::update_tag_option::builders::UpdateTagOptionInputBuilder {
        crate::operation::update_tag_option::builders::UpdateTagOptionInputBuilder::default()
    }
}

/// A builder for [`UpdateTagOptionInput`](crate::operation::update_tag_option::UpdateTagOptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateTagOptionInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) active: ::std::option::Option<bool>,
}
impl UpdateTagOptionInputBuilder {
    /// <p>The TagOption identifier.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The TagOption identifier.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The TagOption identifier.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The updated value.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The updated value.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The updated value.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>The updated active state.</p>
    pub fn active(mut self, input: bool) -> Self {
        self.active = ::std::option::Option::Some(input);
        self
    }
    /// <p>The updated active state.</p>
    pub fn set_active(mut self, input: ::std::option::Option<bool>) -> Self {
        self.active = input;
        self
    }
    /// <p>The updated active state.</p>
    pub fn get_active(&self) -> &::std::option::Option<bool> {
        &self.active
    }
    /// Consumes the builder and constructs a [`UpdateTagOptionInput`](crate::operation::update_tag_option::UpdateTagOptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_tag_option::UpdateTagOptionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_tag_option::UpdateTagOptionInput {
            id: self.id,
            value: self.value,
            active: self.active,
        })
    }
}
