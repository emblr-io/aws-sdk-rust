// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchCreateVariableInput {
    /// <p>The list of variables for the batch create variable request.</p>
    pub variable_entries: ::std::option::Option<::std::vec::Vec<crate::types::VariableEntry>>,
    /// <p>A collection of key and value pairs.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl BatchCreateVariableInput {
    /// <p>The list of variables for the batch create variable request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.variable_entries.is_none()`.
    pub fn variable_entries(&self) -> &[crate::types::VariableEntry] {
        self.variable_entries.as_deref().unwrap_or_default()
    }
    /// <p>A collection of key and value pairs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl BatchCreateVariableInput {
    /// Creates a new builder-style object to manufacture [`BatchCreateVariableInput`](crate::operation::batch_create_variable::BatchCreateVariableInput).
    pub fn builder() -> crate::operation::batch_create_variable::builders::BatchCreateVariableInputBuilder {
        crate::operation::batch_create_variable::builders::BatchCreateVariableInputBuilder::default()
    }
}

/// A builder for [`BatchCreateVariableInput`](crate::operation::batch_create_variable::BatchCreateVariableInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchCreateVariableInputBuilder {
    pub(crate) variable_entries: ::std::option::Option<::std::vec::Vec<crate::types::VariableEntry>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl BatchCreateVariableInputBuilder {
    /// Appends an item to `variable_entries`.
    ///
    /// To override the contents of this collection use [`set_variable_entries`](Self::set_variable_entries).
    ///
    /// <p>The list of variables for the batch create variable request.</p>
    pub fn variable_entries(mut self, input: crate::types::VariableEntry) -> Self {
        let mut v = self.variable_entries.unwrap_or_default();
        v.push(input);
        self.variable_entries = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of variables for the batch create variable request.</p>
    pub fn set_variable_entries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::VariableEntry>>) -> Self {
        self.variable_entries = input;
        self
    }
    /// <p>The list of variables for the batch create variable request.</p>
    pub fn get_variable_entries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::VariableEntry>> {
        &self.variable_entries
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A collection of key and value pairs.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A collection of key and value pairs.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A collection of key and value pairs.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`BatchCreateVariableInput`](crate::operation::batch_create_variable::BatchCreateVariableInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::batch_create_variable::BatchCreateVariableInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::batch_create_variable::BatchCreateVariableInput {
            variable_entries: self.variable_entries,
            tags: self.tags,
        })
    }
}
