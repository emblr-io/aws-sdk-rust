// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of categorical hyperparameters to tune.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CategoricalParameterRange {
    /// <p>The name of the categorical hyperparameter to tune.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A list of the categories for the hyperparameter.</p>
    pub values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CategoricalParameterRange {
    /// <p>The name of the categorical hyperparameter to tune.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A list of the categories for the hyperparameter.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.values.is_none()`.
    pub fn values(&self) -> &[::std::string::String] {
        self.values.as_deref().unwrap_or_default()
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
    /// <p>A list of the categories for the hyperparameter.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the categories for the hyperparameter.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>A list of the categories for the hyperparameter.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`CategoricalParameterRange`](crate::types::CategoricalParameterRange).
    pub fn build(self) -> crate::types::CategoricalParameterRange {
        crate::types::CategoricalParameterRange {
            name: self.name,
            values: self.values,
        }
    }
}
