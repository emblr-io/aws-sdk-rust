// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that contains details about a static policy. It includes the description and policy statement.</p>
/// <p>This data type is used within a <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_PolicyDefinition.html">PolicyDefinition</a> structure as part of a request parameter for the <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_CreatePolicy.html">CreatePolicy</a> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct StaticPolicyDefinitionItem {
    /// <p>A description of the static policy.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl StaticPolicyDefinitionItem {
    /// <p>A description of the static policy.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl ::std::fmt::Debug for StaticPolicyDefinitionItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StaticPolicyDefinitionItem");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl StaticPolicyDefinitionItem {
    /// Creates a new builder-style object to manufacture [`StaticPolicyDefinitionItem`](crate::types::StaticPolicyDefinitionItem).
    pub fn builder() -> crate::types::builders::StaticPolicyDefinitionItemBuilder {
        crate::types::builders::StaticPolicyDefinitionItemBuilder::default()
    }
}

/// A builder for [`StaticPolicyDefinitionItem`](crate::types::StaticPolicyDefinitionItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct StaticPolicyDefinitionItemBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl StaticPolicyDefinitionItemBuilder {
    /// <p>A description of the static policy.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the static policy.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the static policy.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`StaticPolicyDefinitionItem`](crate::types::StaticPolicyDefinitionItem).
    pub fn build(self) -> crate::types::StaticPolicyDefinitionItem {
        crate::types::StaticPolicyDefinitionItem {
            description: self.description,
        }
    }
}
impl ::std::fmt::Debug for StaticPolicyDefinitionItemBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StaticPolicyDefinitionItemBuilder");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
