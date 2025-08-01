// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateCalculatedAttributeDefinitionInput {
    /// <p>The unique name of the domain.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique name of the calculated attribute.</p>
    pub calculated_attribute_name: ::std::option::Option<::std::string::String>,
    /// <p>The display name of the calculated attribute.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the calculated attribute.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The conditions including range, object count, and threshold for the calculated attribute.</p>
    pub conditions: ::std::option::Option<crate::types::Conditions>,
}
impl UpdateCalculatedAttributeDefinitionInput {
    /// <p>The unique name of the domain.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>The unique name of the calculated attribute.</p>
    pub fn calculated_attribute_name(&self) -> ::std::option::Option<&str> {
        self.calculated_attribute_name.as_deref()
    }
    /// <p>The display name of the calculated attribute.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>The description of the calculated attribute.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The conditions including range, object count, and threshold for the calculated attribute.</p>
    pub fn conditions(&self) -> ::std::option::Option<&crate::types::Conditions> {
        self.conditions.as_ref()
    }
}
impl ::std::fmt::Debug for UpdateCalculatedAttributeDefinitionInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateCalculatedAttributeDefinitionInput");
        formatter.field("domain_name", &self.domain_name);
        formatter.field("calculated_attribute_name", &self.calculated_attribute_name);
        formatter.field("display_name", &self.display_name);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("conditions", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl UpdateCalculatedAttributeDefinitionInput {
    /// Creates a new builder-style object to manufacture [`UpdateCalculatedAttributeDefinitionInput`](crate::operation::update_calculated_attribute_definition::UpdateCalculatedAttributeDefinitionInput).
    pub fn builder() -> crate::operation::update_calculated_attribute_definition::builders::UpdateCalculatedAttributeDefinitionInputBuilder {
        crate::operation::update_calculated_attribute_definition::builders::UpdateCalculatedAttributeDefinitionInputBuilder::default()
    }
}

/// A builder for [`UpdateCalculatedAttributeDefinitionInput`](crate::operation::update_calculated_attribute_definition::UpdateCalculatedAttributeDefinitionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateCalculatedAttributeDefinitionInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) calculated_attribute_name: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) conditions: ::std::option::Option<crate::types::Conditions>,
}
impl UpdateCalculatedAttributeDefinitionInputBuilder {
    /// <p>The unique name of the domain.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique name of the domain.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The unique name of the domain.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>The unique name of the calculated attribute.</p>
    /// This field is required.
    pub fn calculated_attribute_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.calculated_attribute_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique name of the calculated attribute.</p>
    pub fn set_calculated_attribute_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.calculated_attribute_name = input;
        self
    }
    /// <p>The unique name of the calculated attribute.</p>
    pub fn get_calculated_attribute_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.calculated_attribute_name
    }
    /// <p>The display name of the calculated attribute.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of the calculated attribute.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The display name of the calculated attribute.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>The description of the calculated attribute.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the calculated attribute.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the calculated attribute.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The conditions including range, object count, and threshold for the calculated attribute.</p>
    pub fn conditions(mut self, input: crate::types::Conditions) -> Self {
        self.conditions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The conditions including range, object count, and threshold for the calculated attribute.</p>
    pub fn set_conditions(mut self, input: ::std::option::Option<crate::types::Conditions>) -> Self {
        self.conditions = input;
        self
    }
    /// <p>The conditions including range, object count, and threshold for the calculated attribute.</p>
    pub fn get_conditions(&self) -> &::std::option::Option<crate::types::Conditions> {
        &self.conditions
    }
    /// Consumes the builder and constructs a [`UpdateCalculatedAttributeDefinitionInput`](crate::operation::update_calculated_attribute_definition::UpdateCalculatedAttributeDefinitionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_calculated_attribute_definition::UpdateCalculatedAttributeDefinitionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::update_calculated_attribute_definition::UpdateCalculatedAttributeDefinitionInput {
                domain_name: self.domain_name,
                calculated_attribute_name: self.calculated_attribute_name,
                display_name: self.display_name,
                description: self.description,
                conditions: self.conditions,
            },
        )
    }
}
impl ::std::fmt::Debug for UpdateCalculatedAttributeDefinitionInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateCalculatedAttributeDefinitionInputBuilder");
        formatter.field("domain_name", &self.domain_name);
        formatter.field("calculated_attribute_name", &self.calculated_attribute_name);
        formatter.field("display_name", &self.display_name);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("conditions", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
