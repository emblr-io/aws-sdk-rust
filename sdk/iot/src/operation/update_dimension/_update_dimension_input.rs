// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDimensionInput {
    /// <p>A unique identifier for the dimension. Choose something that describes the type and value to make it easy to remember what it does.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the value or list of values for the dimension. For <code>TOPIC_FILTER</code> dimensions, this is a pattern used to match the MQTT topic (for example, "admin/#").</p>
    pub string_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UpdateDimensionInput {
    /// <p>A unique identifier for the dimension. Choose something that describes the type and value to make it easy to remember what it does.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Specifies the value or list of values for the dimension. For <code>TOPIC_FILTER</code> dimensions, this is a pattern used to match the MQTT topic (for example, "admin/#").</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.string_values.is_none()`.
    pub fn string_values(&self) -> &[::std::string::String] {
        self.string_values.as_deref().unwrap_or_default()
    }
}
impl UpdateDimensionInput {
    /// Creates a new builder-style object to manufacture [`UpdateDimensionInput`](crate::operation::update_dimension::UpdateDimensionInput).
    pub fn builder() -> crate::operation::update_dimension::builders::UpdateDimensionInputBuilder {
        crate::operation::update_dimension::builders::UpdateDimensionInputBuilder::default()
    }
}

/// A builder for [`UpdateDimensionInput`](crate::operation::update_dimension::UpdateDimensionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDimensionInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) string_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UpdateDimensionInputBuilder {
    /// <p>A unique identifier for the dimension. Choose something that describes the type and value to make it easy to remember what it does.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the dimension. Choose something that describes the type and value to make it easy to remember what it does.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A unique identifier for the dimension. Choose something that describes the type and value to make it easy to remember what it does.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `string_values`.
    ///
    /// To override the contents of this collection use [`set_string_values`](Self::set_string_values).
    ///
    /// <p>Specifies the value or list of values for the dimension. For <code>TOPIC_FILTER</code> dimensions, this is a pattern used to match the MQTT topic (for example, "admin/#").</p>
    pub fn string_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.string_values.unwrap_or_default();
        v.push(input.into());
        self.string_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the value or list of values for the dimension. For <code>TOPIC_FILTER</code> dimensions, this is a pattern used to match the MQTT topic (for example, "admin/#").</p>
    pub fn set_string_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.string_values = input;
        self
    }
    /// <p>Specifies the value or list of values for the dimension. For <code>TOPIC_FILTER</code> dimensions, this is a pattern used to match the MQTT topic (for example, "admin/#").</p>
    pub fn get_string_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.string_values
    }
    /// Consumes the builder and constructs a [`UpdateDimensionInput`](crate::operation::update_dimension::UpdateDimensionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_dimension::UpdateDimensionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_dimension::UpdateDimensionInput {
            name: self.name,
            string_values: self.string_values,
        })
    }
}
