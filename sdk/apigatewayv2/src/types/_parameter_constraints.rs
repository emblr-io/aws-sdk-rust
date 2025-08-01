// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Validation constraints imposed on parameters of a request (path, query string, headers).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ParameterConstraints {
    /// <p>Whether or not the parameter is required.</p>
    pub required: ::std::option::Option<bool>,
}
impl ParameterConstraints {
    /// <p>Whether or not the parameter is required.</p>
    pub fn required(&self) -> ::std::option::Option<bool> {
        self.required
    }
}
impl ParameterConstraints {
    /// Creates a new builder-style object to manufacture [`ParameterConstraints`](crate::types::ParameterConstraints).
    pub fn builder() -> crate::types::builders::ParameterConstraintsBuilder {
        crate::types::builders::ParameterConstraintsBuilder::default()
    }
}

/// A builder for [`ParameterConstraints`](crate::types::ParameterConstraints).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ParameterConstraintsBuilder {
    pub(crate) required: ::std::option::Option<bool>,
}
impl ParameterConstraintsBuilder {
    /// <p>Whether or not the parameter is required.</p>
    pub fn required(mut self, input: bool) -> Self {
        self.required = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether or not the parameter is required.</p>
    pub fn set_required(mut self, input: ::std::option::Option<bool>) -> Self {
        self.required = input;
        self
    }
    /// <p>Whether or not the parameter is required.</p>
    pub fn get_required(&self) -> &::std::option::Option<bool> {
        &self.required
    }
    /// Consumes the builder and constructs a [`ParameterConstraints`](crate::types::ParameterConstraints).
    pub fn build(self) -> crate::types::ParameterConstraints {
        crate::types::ParameterConstraints { required: self.required }
    }
}
