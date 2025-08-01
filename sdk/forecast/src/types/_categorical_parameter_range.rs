// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a categorical hyperparameter and it's range of tunable values. This object is part of the <code>ParameterRanges</code> object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CategoricalParameterRange {
    /// <p>The name of the categorical hyperparameter to tune.</p>
    pub name: ::std::string::String,
    /// <p>A list of the tunable categories for the hyperparameter.</p>
    pub values: ::std::vec::Vec<::std::string::String>,
}
impl CategoricalParameterRange {
    /// <p>The name of the categorical hyperparameter to tune.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>A list of the tunable categories for the hyperparameter.</p>
    pub fn values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.values.deref()
    }
}
impl CategoricalParameterRange {
    /// Creates a new builder-style object to manufacture [`CategoricalParameterRange`](crate::types::CategoricalParameterRange).
    pub fn builder() -> crate::types::builders::CategoricalParameterRangeBuilder {
        crate::types::builders::CategoricalParameterRangeBuilder::default()
    }
}

/// A builder for [`CategoricalParameterRange`](crate::types::CategoricalParameterRange).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CategoricalParameterRangeBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CategoricalParameterRangeBuilder {
    /// <p>The name of the categorical hyperparameter to tune.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the categorical hyperparameter to tune.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the categorical hyperparameter to tune.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>A list of the tunable categories for the hyperparameter.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the tunable categories for the hyperparameter.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>A list of the tunable categories for the hyperparameter.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`CategoricalParameterRange`](crate::types::CategoricalParameterRange).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::CategoricalParameterRangeBuilder::name)
    /// - [`values`](crate::types::builders::CategoricalParameterRangeBuilder::values)
    pub fn build(self) -> ::std::result::Result<crate::types::CategoricalParameterRange, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CategoricalParameterRange {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building CategoricalParameterRange",
                )
            })?,
            values: self.values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values",
                    "values was not specified but it is required when building CategoricalParameterRange",
                )
            })?,
        })
    }
}
