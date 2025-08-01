// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A field that details a specification of a deployment pattern.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeploymentSpecificationsField {
    /// <p>The name of the deployment specification.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the deployment specification.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The allowed values of the deployment specification.</p>
    pub allowed_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Indicates if the deployment specification is required.</p>
    pub required: ::std::option::Option<::std::string::String>,
    /// <p>The conditionals used for the deployment specification.</p>
    pub conditionals: ::std::option::Option<::std::vec::Vec<crate::types::DeploymentConditionalField>>,
}
impl DeploymentSpecificationsField {
    /// <p>The name of the deployment specification.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the deployment specification.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The allowed values of the deployment specification.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.allowed_values.is_none()`.
    pub fn allowed_values(&self) -> &[::std::string::String] {
        self.allowed_values.as_deref().unwrap_or_default()
    }
    /// <p>Indicates if the deployment specification is required.</p>
    pub fn required(&self) -> ::std::option::Option<&str> {
        self.required.as_deref()
    }
    /// <p>The conditionals used for the deployment specification.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.conditionals.is_none()`.
    pub fn conditionals(&self) -> &[crate::types::DeploymentConditionalField] {
        self.conditionals.as_deref().unwrap_or_default()
    }
}
impl DeploymentSpecificationsField {
    /// Creates a new builder-style object to manufacture [`DeploymentSpecificationsField`](crate::types::DeploymentSpecificationsField).
    pub fn builder() -> crate::types::builders::DeploymentSpecificationsFieldBuilder {
        crate::types::builders::DeploymentSpecificationsFieldBuilder::default()
    }
}

/// A builder for [`DeploymentSpecificationsField`](crate::types::DeploymentSpecificationsField).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeploymentSpecificationsFieldBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) allowed_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) required: ::std::option::Option<::std::string::String>,
    pub(crate) conditionals: ::std::option::Option<::std::vec::Vec<crate::types::DeploymentConditionalField>>,
}
impl DeploymentSpecificationsFieldBuilder {
    /// <p>The name of the deployment specification.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the deployment specification.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the deployment specification.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the deployment specification.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the deployment specification.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the deployment specification.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `allowed_values`.
    ///
    /// To override the contents of this collection use [`set_allowed_values`](Self::set_allowed_values).
    ///
    /// <p>The allowed values of the deployment specification.</p>
    pub fn allowed_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.allowed_values.unwrap_or_default();
        v.push(input.into());
        self.allowed_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The allowed values of the deployment specification.</p>
    pub fn set_allowed_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.allowed_values = input;
        self
    }
    /// <p>The allowed values of the deployment specification.</p>
    pub fn get_allowed_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.allowed_values
    }
    /// <p>Indicates if the deployment specification is required.</p>
    pub fn required(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.required = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates if the deployment specification is required.</p>
    pub fn set_required(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.required = input;
        self
    }
    /// <p>Indicates if the deployment specification is required.</p>
    pub fn get_required(&self) -> &::std::option::Option<::std::string::String> {
        &self.required
    }
    /// Appends an item to `conditionals`.
    ///
    /// To override the contents of this collection use [`set_conditionals`](Self::set_conditionals).
    ///
    /// <p>The conditionals used for the deployment specification.</p>
    pub fn conditionals(mut self, input: crate::types::DeploymentConditionalField) -> Self {
        let mut v = self.conditionals.unwrap_or_default();
        v.push(input);
        self.conditionals = ::std::option::Option::Some(v);
        self
    }
    /// <p>The conditionals used for the deployment specification.</p>
    pub fn set_conditionals(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DeploymentConditionalField>>) -> Self {
        self.conditionals = input;
        self
    }
    /// <p>The conditionals used for the deployment specification.</p>
    pub fn get_conditionals(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DeploymentConditionalField>> {
        &self.conditionals
    }
    /// Consumes the builder and constructs a [`DeploymentSpecificationsField`](crate::types::DeploymentSpecificationsField).
    pub fn build(self) -> crate::types::DeploymentSpecificationsField {
        crate::types::DeploymentSpecificationsField {
            name: self.name,
            description: self.description,
            allowed_values: self.allowed_values,
            required: self.required,
            conditionals: self.conditionals,
        }
    }
}
