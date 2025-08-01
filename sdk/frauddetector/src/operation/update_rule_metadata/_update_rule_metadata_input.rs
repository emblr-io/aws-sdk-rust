// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateRuleMetadataInput {
    /// <p>The rule to update.</p>
    pub rule: ::std::option::Option<crate::types::Rule>,
    /// <p>The rule description.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl UpdateRuleMetadataInput {
    /// <p>The rule to update.</p>
    pub fn rule(&self) -> ::std::option::Option<&crate::types::Rule> {
        self.rule.as_ref()
    }
    /// <p>The rule description.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl UpdateRuleMetadataInput {
    /// Creates a new builder-style object to manufacture [`UpdateRuleMetadataInput`](crate::operation::update_rule_metadata::UpdateRuleMetadataInput).
    pub fn builder() -> crate::operation::update_rule_metadata::builders::UpdateRuleMetadataInputBuilder {
        crate::operation::update_rule_metadata::builders::UpdateRuleMetadataInputBuilder::default()
    }
}

/// A builder for [`UpdateRuleMetadataInput`](crate::operation::update_rule_metadata::UpdateRuleMetadataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateRuleMetadataInputBuilder {
    pub(crate) rule: ::std::option::Option<crate::types::Rule>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl UpdateRuleMetadataInputBuilder {
    /// <p>The rule to update.</p>
    /// This field is required.
    pub fn rule(mut self, input: crate::types::Rule) -> Self {
        self.rule = ::std::option::Option::Some(input);
        self
    }
    /// <p>The rule to update.</p>
    pub fn set_rule(mut self, input: ::std::option::Option<crate::types::Rule>) -> Self {
        self.rule = input;
        self
    }
    /// <p>The rule to update.</p>
    pub fn get_rule(&self) -> &::std::option::Option<crate::types::Rule> {
        &self.rule
    }
    /// <p>The rule description.</p>
    /// This field is required.
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The rule description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The rule description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`UpdateRuleMetadataInput`](crate::operation::update_rule_metadata::UpdateRuleMetadataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_rule_metadata::UpdateRuleMetadataInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_rule_metadata::UpdateRuleMetadataInput {
            rule: self.rule,
            description: self.description,
        })
    }
}
