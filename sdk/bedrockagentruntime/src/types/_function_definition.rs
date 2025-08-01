// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines parameters that the agent needs to invoke from the user to complete the function. Corresponds to an action in an action group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct FunctionDefinition {
    /// <p>A name for the function.</p>
    pub name: ::std::string::String,
    /// <p>A description of the function and its purpose.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The parameters that the agent elicits from the user to fulfill the function.</p>
    pub parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ParameterDetail>>,
    /// <p>Contains information if user confirmation is required to invoke the function.</p>
    pub require_confirmation: ::std::option::Option<crate::types::RequireConfirmation>,
}
impl FunctionDefinition {
    /// <p>A name for the function.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>A description of the function and its purpose.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The parameters that the agent elicits from the user to fulfill the function.</p>
    pub fn parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::ParameterDetail>> {
        self.parameters.as_ref()
    }
    /// <p>Contains information if user confirmation is required to invoke the function.</p>
    pub fn require_confirmation(&self) -> ::std::option::Option<&crate::types::RequireConfirmation> {
        self.require_confirmation.as_ref()
    }
}
impl ::std::fmt::Debug for FunctionDefinition {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("FunctionDefinition");
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &self.description);
        formatter.field("parameters", &self.parameters);
        formatter.field("require_confirmation", &self.require_confirmation);
        formatter.finish()
    }
}
impl FunctionDefinition {
    /// Creates a new builder-style object to manufacture [`FunctionDefinition`](crate::types::FunctionDefinition).
    pub fn builder() -> crate::types::builders::FunctionDefinitionBuilder {
        crate::types::builders::FunctionDefinitionBuilder::default()
    }
}

/// A builder for [`FunctionDefinition`](crate::types::FunctionDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct FunctionDefinitionBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ParameterDetail>>,
    pub(crate) require_confirmation: ::std::option::Option<crate::types::RequireConfirmation>,
}
impl FunctionDefinitionBuilder {
    /// <p>A name for the function.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the function.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A name for the function.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description of the function and its purpose.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the function and its purpose.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the function and its purpose.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Adds a key-value pair to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>The parameters that the agent elicits from the user to fulfill the function.</p>
    pub fn parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::ParameterDetail) -> Self {
        let mut hash_map = self.parameters.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The parameters that the agent elicits from the user to fulfill the function.</p>
    pub fn set_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ParameterDetail>>,
    ) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The parameters that the agent elicits from the user to fulfill the function.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::ParameterDetail>> {
        &self.parameters
    }
    /// <p>Contains information if user confirmation is required to invoke the function.</p>
    pub fn require_confirmation(mut self, input: crate::types::RequireConfirmation) -> Self {
        self.require_confirmation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information if user confirmation is required to invoke the function.</p>
    pub fn set_require_confirmation(mut self, input: ::std::option::Option<crate::types::RequireConfirmation>) -> Self {
        self.require_confirmation = input;
        self
    }
    /// <p>Contains information if user confirmation is required to invoke the function.</p>
    pub fn get_require_confirmation(&self) -> &::std::option::Option<crate::types::RequireConfirmation> {
        &self.require_confirmation
    }
    /// Consumes the builder and constructs a [`FunctionDefinition`](crate::types::FunctionDefinition).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::FunctionDefinitionBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::FunctionDefinition, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FunctionDefinition {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building FunctionDefinition",
                )
            })?,
            description: self.description,
            parameters: self.parameters,
            require_confirmation: self.require_confirmation,
        })
    }
}
impl ::std::fmt::Debug for FunctionDefinitionBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("FunctionDefinitionBuilder");
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &self.description);
        formatter.field("parameters", &self.parameters);
        formatter.field("require_confirmation", &self.require_confirmation);
        formatter.finish()
    }
}
