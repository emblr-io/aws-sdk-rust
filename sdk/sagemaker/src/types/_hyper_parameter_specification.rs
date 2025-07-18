// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a hyperparameter to be used by an algorithm.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HyperParameterSpecification {
    /// <p>The name of this hyperparameter. The name must be unique.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A brief description of the hyperparameter.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The type of this hyperparameter. The valid types are <code>Integer</code>, <code>Continuous</code>, <code>Categorical</code>, and <code>FreeText</code>.</p>
    pub r#type: ::std::option::Option<crate::types::ParameterType>,
    /// <p>The allowed range for this hyperparameter.</p>
    pub range: ::std::option::Option<crate::types::ParameterRange>,
    /// <p>Indicates whether this hyperparameter is tunable in a hyperparameter tuning job.</p>
    pub is_tunable: ::std::option::Option<bool>,
    /// <p>Indicates whether this hyperparameter is required.</p>
    pub is_required: ::std::option::Option<bool>,
    /// <p>The default value for this hyperparameter. If a default value is specified, a hyperparameter cannot be required.</p>
    pub default_value: ::std::option::Option<::std::string::String>,
}
impl HyperParameterSpecification {
    /// <p>The name of this hyperparameter. The name must be unique.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A brief description of the hyperparameter.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The type of this hyperparameter. The valid types are <code>Integer</code>, <code>Continuous</code>, <code>Categorical</code>, and <code>FreeText</code>.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ParameterType> {
        self.r#type.as_ref()
    }
    /// <p>The allowed range for this hyperparameter.</p>
    pub fn range(&self) -> ::std::option::Option<&crate::types::ParameterRange> {
        self.range.as_ref()
    }
    /// <p>Indicates whether this hyperparameter is tunable in a hyperparameter tuning job.</p>
    pub fn is_tunable(&self) -> ::std::option::Option<bool> {
        self.is_tunable
    }
    /// <p>Indicates whether this hyperparameter is required.</p>
    pub fn is_required(&self) -> ::std::option::Option<bool> {
        self.is_required
    }
    /// <p>The default value for this hyperparameter. If a default value is specified, a hyperparameter cannot be required.</p>
    pub fn default_value(&self) -> ::std::option::Option<&str> {
        self.default_value.as_deref()
    }
}
impl HyperParameterSpecification {
    /// Creates a new builder-style object to manufacture [`HyperParameterSpecification`](crate::types::HyperParameterSpecification).
    pub fn builder() -> crate::types::builders::HyperParameterSpecificationBuilder {
        crate::types::builders::HyperParameterSpecificationBuilder::default()
    }
}

/// A builder for [`HyperParameterSpecification`](crate::types::HyperParameterSpecification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HyperParameterSpecificationBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::ParameterType>,
    pub(crate) range: ::std::option::Option<crate::types::ParameterRange>,
    pub(crate) is_tunable: ::std::option::Option<bool>,
    pub(crate) is_required: ::std::option::Option<bool>,
    pub(crate) default_value: ::std::option::Option<::std::string::String>,
}
impl HyperParameterSpecificationBuilder {
    /// <p>The name of this hyperparameter. The name must be unique.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of this hyperparameter. The name must be unique.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of this hyperparameter. The name must be unique.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A brief description of the hyperparameter.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A brief description of the hyperparameter.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A brief description of the hyperparameter.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The type of this hyperparameter. The valid types are <code>Integer</code>, <code>Continuous</code>, <code>Categorical</code>, and <code>FreeText</code>.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::ParameterType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of this hyperparameter. The valid types are <code>Integer</code>, <code>Continuous</code>, <code>Categorical</code>, and <code>FreeText</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ParameterType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of this hyperparameter. The valid types are <code>Integer</code>, <code>Continuous</code>, <code>Categorical</code>, and <code>FreeText</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ParameterType> {
        &self.r#type
    }
    /// <p>The allowed range for this hyperparameter.</p>
    pub fn range(mut self, input: crate::types::ParameterRange) -> Self {
        self.range = ::std::option::Option::Some(input);
        self
    }
    /// <p>The allowed range for this hyperparameter.</p>
    pub fn set_range(mut self, input: ::std::option::Option<crate::types::ParameterRange>) -> Self {
        self.range = input;
        self
    }
    /// <p>The allowed range for this hyperparameter.</p>
    pub fn get_range(&self) -> &::std::option::Option<crate::types::ParameterRange> {
        &self.range
    }
    /// <p>Indicates whether this hyperparameter is tunable in a hyperparameter tuning job.</p>
    pub fn is_tunable(mut self, input: bool) -> Self {
        self.is_tunable = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether this hyperparameter is tunable in a hyperparameter tuning job.</p>
    pub fn set_is_tunable(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_tunable = input;
        self
    }
    /// <p>Indicates whether this hyperparameter is tunable in a hyperparameter tuning job.</p>
    pub fn get_is_tunable(&self) -> &::std::option::Option<bool> {
        &self.is_tunable
    }
    /// <p>Indicates whether this hyperparameter is required.</p>
    pub fn is_required(mut self, input: bool) -> Self {
        self.is_required = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether this hyperparameter is required.</p>
    pub fn set_is_required(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_required = input;
        self
    }
    /// <p>Indicates whether this hyperparameter is required.</p>
    pub fn get_is_required(&self) -> &::std::option::Option<bool> {
        &self.is_required
    }
    /// <p>The default value for this hyperparameter. If a default value is specified, a hyperparameter cannot be required.</p>
    pub fn default_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The default value for this hyperparameter. If a default value is specified, a hyperparameter cannot be required.</p>
    pub fn set_default_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_value = input;
        self
    }
    /// <p>The default value for this hyperparameter. If a default value is specified, a hyperparameter cannot be required.</p>
    pub fn get_default_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_value
    }
    /// Consumes the builder and constructs a [`HyperParameterSpecification`](crate::types::HyperParameterSpecification).
    pub fn build(self) -> crate::types::HyperParameterSpecification {
        crate::types::HyperParameterSpecification {
            name: self.name,
            description: self.description,
            r#type: self.r#type,
            range: self.range,
            is_tunable: self.is_tunable,
            is_required: self.is_required,
            default_value: self.default_value,
        }
    }
}
