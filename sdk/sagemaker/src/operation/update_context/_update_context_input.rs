// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateContextInput {
    /// <p>The name of the context to update.</p>
    pub context_name: ::std::option::Option<::std::string::String>,
    /// <p>The new description for the context.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The new list of properties. Overwrites the current property list.</p>
    pub properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>A list of properties to remove.</p>
    pub properties_to_remove: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UpdateContextInput {
    /// <p>The name of the context to update.</p>
    pub fn context_name(&self) -> ::std::option::Option<&str> {
        self.context_name.as_deref()
    }
    /// <p>The new description for the context.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The new list of properties. Overwrites the current property list.</p>
    pub fn properties(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.properties.as_ref()
    }
    /// <p>A list of properties to remove.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.properties_to_remove.is_none()`.
    pub fn properties_to_remove(&self) -> &[::std::string::String] {
        self.properties_to_remove.as_deref().unwrap_or_default()
    }
}
impl UpdateContextInput {
    /// Creates a new builder-style object to manufacture [`UpdateContextInput`](crate::operation::update_context::UpdateContextInput).
    pub fn builder() -> crate::operation::update_context::builders::UpdateContextInputBuilder {
        crate::operation::update_context::builders::UpdateContextInputBuilder::default()
    }
}

/// A builder for [`UpdateContextInput`](crate::operation::update_context::UpdateContextInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateContextInputBuilder {
    pub(crate) context_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) properties_to_remove: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UpdateContextInputBuilder {
    /// <p>The name of the context to update.</p>
    /// This field is required.
    pub fn context_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.context_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the context to update.</p>
    pub fn set_context_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.context_name = input;
        self
    }
    /// <p>The name of the context to update.</p>
    pub fn get_context_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.context_name
    }
    /// <p>The new description for the context.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new description for the context.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The new description for the context.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Adds a key-value pair to `properties`.
    ///
    /// To override the contents of this collection use [`set_properties`](Self::set_properties).
    ///
    /// <p>The new list of properties. Overwrites the current property list.</p>
    pub fn properties(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.properties.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.properties = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The new list of properties. Overwrites the current property list.</p>
    pub fn set_properties(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.properties = input;
        self
    }
    /// <p>The new list of properties. Overwrites the current property list.</p>
    pub fn get_properties(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.properties
    }
    /// Appends an item to `properties_to_remove`.
    ///
    /// To override the contents of this collection use [`set_properties_to_remove`](Self::set_properties_to_remove).
    ///
    /// <p>A list of properties to remove.</p>
    pub fn properties_to_remove(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.properties_to_remove.unwrap_or_default();
        v.push(input.into());
        self.properties_to_remove = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of properties to remove.</p>
    pub fn set_properties_to_remove(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.properties_to_remove = input;
        self
    }
    /// <p>A list of properties to remove.</p>
    pub fn get_properties_to_remove(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.properties_to_remove
    }
    /// Consumes the builder and constructs a [`UpdateContextInput`](crate::operation::update_context::UpdateContextInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_context::UpdateContextInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_context::UpdateContextInput {
            context_name: self.context_name,
            description: self.description,
            properties: self.properties,
            properties_to_remove: self.properties_to_remove,
        })
    }
}
