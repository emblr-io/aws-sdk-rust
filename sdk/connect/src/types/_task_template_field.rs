// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a single task template field.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TaskTemplateField {
    /// <p>The unique identifier for the field.</p>
    pub id: ::std::option::Option<crate::types::TaskTemplateFieldIdentifier>,
    /// <p>The description of the field.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the type of field.</p>
    pub r#type: ::std::option::Option<crate::types::TaskTemplateFieldType>,
    /// <p>A list of options for a single select field.</p>
    pub single_select_options: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl TaskTemplateField {
    /// <p>The unique identifier for the field.</p>
    pub fn id(&self) -> ::std::option::Option<&crate::types::TaskTemplateFieldIdentifier> {
        self.id.as_ref()
    }
    /// <p>The description of the field.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Indicates the type of field.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::TaskTemplateFieldType> {
        self.r#type.as_ref()
    }
    /// <p>A list of options for a single select field.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.single_select_options.is_none()`.
    pub fn single_select_options(&self) -> &[::std::string::String] {
        self.single_select_options.as_deref().unwrap_or_default()
    }
}
impl TaskTemplateField {
    /// Creates a new builder-style object to manufacture [`TaskTemplateField`](crate::types::TaskTemplateField).
    pub fn builder() -> crate::types::builders::TaskTemplateFieldBuilder {
        crate::types::builders::TaskTemplateFieldBuilder::default()
    }
}

/// A builder for [`TaskTemplateField`](crate::types::TaskTemplateField).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TaskTemplateFieldBuilder {
    pub(crate) id: ::std::option::Option<crate::types::TaskTemplateFieldIdentifier>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::TaskTemplateFieldType>,
    pub(crate) single_select_options: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl TaskTemplateFieldBuilder {
    /// <p>The unique identifier for the field.</p>
    /// This field is required.
    pub fn id(mut self, input: crate::types::TaskTemplateFieldIdentifier) -> Self {
        self.id = ::std::option::Option::Some(input);
        self
    }
    /// <p>The unique identifier for the field.</p>
    pub fn set_id(mut self, input: ::std::option::Option<crate::types::TaskTemplateFieldIdentifier>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier for the field.</p>
    pub fn get_id(&self) -> &::std::option::Option<crate::types::TaskTemplateFieldIdentifier> {
        &self.id
    }
    /// <p>The description of the field.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the field.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the field.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Indicates the type of field.</p>
    pub fn r#type(mut self, input: crate::types::TaskTemplateFieldType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the type of field.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::TaskTemplateFieldType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Indicates the type of field.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::TaskTemplateFieldType> {
        &self.r#type
    }
    /// Appends an item to `single_select_options`.
    ///
    /// To override the contents of this collection use [`set_single_select_options`](Self::set_single_select_options).
    ///
    /// <p>A list of options for a single select field.</p>
    pub fn single_select_options(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.single_select_options.unwrap_or_default();
        v.push(input.into());
        self.single_select_options = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of options for a single select field.</p>
    pub fn set_single_select_options(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.single_select_options = input;
        self
    }
    /// <p>A list of options for a single select field.</p>
    pub fn get_single_select_options(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.single_select_options
    }
    /// Consumes the builder and constructs a [`TaskTemplateField`](crate::types::TaskTemplateField).
    pub fn build(self) -> crate::types::TaskTemplateField {
        crate::types::TaskTemplateField {
            id: self.id,
            description: self.description,
            r#type: self.r#type,
            single_select_options: self.single_select_options,
        }
    }
}
