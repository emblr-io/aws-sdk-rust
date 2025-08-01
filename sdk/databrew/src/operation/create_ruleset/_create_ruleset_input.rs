// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRulesetInput {
    /// <p>The name of the ruleset to be created. Valid characters are alphanumeric (A-Z, a-z, 0-9), hyphen (-), period (.), and space.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the ruleset.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of a resource (dataset) that the ruleset is associated with.</p>
    pub target_arn: ::std::option::Option<::std::string::String>,
    /// <p>A list of rules that are defined with the ruleset. A rule includes one or more checks to be validated on a DataBrew dataset.</p>
    pub rules: ::std::option::Option<::std::vec::Vec<crate::types::Rule>>,
    /// <p>Metadata tags to apply to the ruleset.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateRulesetInput {
    /// <p>The name of the ruleset to be created. Valid characters are alphanumeric (A-Z, a-z, 0-9), hyphen (-), period (.), and space.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the ruleset.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of a resource (dataset) that the ruleset is associated with.</p>
    pub fn target_arn(&self) -> ::std::option::Option<&str> {
        self.target_arn.as_deref()
    }
    /// <p>A list of rules that are defined with the ruleset. A rule includes one or more checks to be validated on a DataBrew dataset.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rules.is_none()`.
    pub fn rules(&self) -> &[crate::types::Rule] {
        self.rules.as_deref().unwrap_or_default()
    }
    /// <p>Metadata tags to apply to the ruleset.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateRulesetInput {
    /// Creates a new builder-style object to manufacture [`CreateRulesetInput`](crate::operation::create_ruleset::CreateRulesetInput).
    pub fn builder() -> crate::operation::create_ruleset::builders::CreateRulesetInputBuilder {
        crate::operation::create_ruleset::builders::CreateRulesetInputBuilder::default()
    }
}

/// A builder for [`CreateRulesetInput`](crate::operation::create_ruleset::CreateRulesetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRulesetInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) target_arn: ::std::option::Option<::std::string::String>,
    pub(crate) rules: ::std::option::Option<::std::vec::Vec<crate::types::Rule>>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateRulesetInputBuilder {
    /// <p>The name of the ruleset to be created. Valid characters are alphanumeric (A-Z, a-z, 0-9), hyphen (-), period (.), and space.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the ruleset to be created. Valid characters are alphanumeric (A-Z, a-z, 0-9), hyphen (-), period (.), and space.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the ruleset to be created. Valid characters are alphanumeric (A-Z, a-z, 0-9), hyphen (-), period (.), and space.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the ruleset.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the ruleset.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the ruleset.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The Amazon Resource Name (ARN) of a resource (dataset) that the ruleset is associated with.</p>
    /// This field is required.
    pub fn target_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a resource (dataset) that the ruleset is associated with.</p>
    pub fn set_target_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a resource (dataset) that the ruleset is associated with.</p>
    pub fn get_target_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_arn
    }
    /// Appends an item to `rules`.
    ///
    /// To override the contents of this collection use [`set_rules`](Self::set_rules).
    ///
    /// <p>A list of rules that are defined with the ruleset. A rule includes one or more checks to be validated on a DataBrew dataset.</p>
    pub fn rules(mut self, input: crate::types::Rule) -> Self {
        let mut v = self.rules.unwrap_or_default();
        v.push(input);
        self.rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of rules that are defined with the ruleset. A rule includes one or more checks to be validated on a DataBrew dataset.</p>
    pub fn set_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Rule>>) -> Self {
        self.rules = input;
        self
    }
    /// <p>A list of rules that are defined with the ruleset. A rule includes one or more checks to be validated on a DataBrew dataset.</p>
    pub fn get_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Rule>> {
        &self.rules
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Metadata tags to apply to the ruleset.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Metadata tags to apply to the ruleset.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Metadata tags to apply to the ruleset.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateRulesetInput`](crate::operation::create_ruleset::CreateRulesetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_ruleset::CreateRulesetInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_ruleset::CreateRulesetInput {
            name: self.name,
            description: self.description,
            target_arn: self.target_arn,
            rules: self.rules,
            tags: self.tags,
        })
    }
}
