// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A string parameter for a dataset.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StringDatasetParameter {
    /// <p>An identifier for the string parameter that is created in the dataset.</p>
    pub id: ::std::string::String,
    /// <p>The name of the string parameter that is created in the dataset.</p>
    pub name: ::std::string::String,
    /// <p>The value type of the dataset parameter. Valid values are <code>single value</code> or <code>multi value</code>.</p>
    pub value_type: crate::types::DatasetParameterValueType,
    /// <p>A list of default values for a given string dataset parameter type. This structure only accepts static values.</p>
    pub default_values: ::std::option::Option<crate::types::StringDatasetParameterDefaultValues>,
}
impl StringDatasetParameter {
    /// <p>An identifier for the string parameter that is created in the dataset.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The name of the string parameter that is created in the dataset.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The value type of the dataset parameter. Valid values are <code>single value</code> or <code>multi value</code>.</p>
    pub fn value_type(&self) -> &crate::types::DatasetParameterValueType {
        &self.value_type
    }
    /// <p>A list of default values for a given string dataset parameter type. This structure only accepts static values.</p>
    pub fn default_values(&self) -> ::std::option::Option<&crate::types::StringDatasetParameterDefaultValues> {
        self.default_values.as_ref()
    }
}
impl StringDatasetParameter {
    /// Creates a new builder-style object to manufacture [`StringDatasetParameter`](crate::types::StringDatasetParameter).
    pub fn builder() -> crate::types::builders::StringDatasetParameterBuilder {
        crate::types::builders::StringDatasetParameterBuilder::default()
    }
}

/// A builder for [`StringDatasetParameter`](crate::types::StringDatasetParameter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StringDatasetParameterBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) value_type: ::std::option::Option<crate::types::DatasetParameterValueType>,
    pub(crate) default_values: ::std::option::Option<crate::types::StringDatasetParameterDefaultValues>,
}
impl StringDatasetParameterBuilder {
    /// <p>An identifier for the string parameter that is created in the dataset.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier for the string parameter that is created in the dataset.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>An identifier for the string parameter that is created in the dataset.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the string parameter that is created in the dataset.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the string parameter that is created in the dataset.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the string parameter that is created in the dataset.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The value type of the dataset parameter. Valid values are <code>single value</code> or <code>multi value</code>.</p>
    /// This field is required.
    pub fn value_type(mut self, input: crate::types::DatasetParameterValueType) -> Self {
        self.value_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value type of the dataset parameter. Valid values are <code>single value</code> or <code>multi value</code>.</p>
    pub fn set_value_type(mut self, input: ::std::option::Option<crate::types::DatasetParameterValueType>) -> Self {
        self.value_type = input;
        self
    }
    /// <p>The value type of the dataset parameter. Valid values are <code>single value</code> or <code>multi value</code>.</p>
    pub fn get_value_type(&self) -> &::std::option::Option<crate::types::DatasetParameterValueType> {
        &self.value_type
    }
    /// <p>A list of default values for a given string dataset parameter type. This structure only accepts static values.</p>
    pub fn default_values(mut self, input: crate::types::StringDatasetParameterDefaultValues) -> Self {
        self.default_values = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of default values for a given string dataset parameter type. This structure only accepts static values.</p>
    pub fn set_default_values(mut self, input: ::std::option::Option<crate::types::StringDatasetParameterDefaultValues>) -> Self {
        self.default_values = input;
        self
    }
    /// <p>A list of default values for a given string dataset parameter type. This structure only accepts static values.</p>
    pub fn get_default_values(&self) -> &::std::option::Option<crate::types::StringDatasetParameterDefaultValues> {
        &self.default_values
    }
    /// Consumes the builder and constructs a [`StringDatasetParameter`](crate::types::StringDatasetParameter).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::StringDatasetParameterBuilder::id)
    /// - [`name`](crate::types::builders::StringDatasetParameterBuilder::name)
    /// - [`value_type`](crate::types::builders::StringDatasetParameterBuilder::value_type)
    pub fn build(self) -> ::std::result::Result<crate::types::StringDatasetParameter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::StringDatasetParameter {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building StringDatasetParameter",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building StringDatasetParameter",
                )
            })?,
            value_type: self.value_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value_type",
                    "value_type was not specified but it is required when building StringDatasetParameter",
                )
            })?,
            default_values: self.default_values,
        })
    }
}
