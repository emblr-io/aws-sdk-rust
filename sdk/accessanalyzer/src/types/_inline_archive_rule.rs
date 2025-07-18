// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An criterion statement in an archive rule. Each archive rule may have multiple criteria.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InlineArchiveRule {
    /// <p>The name of the rule.</p>
    pub rule_name: ::std::string::String,
    /// <p>The condition and values for a criterion.</p>
    pub filter: ::std::collections::HashMap<::std::string::String, crate::types::Criterion>,
}
impl InlineArchiveRule {
    /// <p>The name of the rule.</p>
    pub fn rule_name(&self) -> &str {
        use std::ops::Deref;
        self.rule_name.deref()
    }
    /// <p>The condition and values for a criterion.</p>
    pub fn filter(&self) -> &::std::collections::HashMap<::std::string::String, crate::types::Criterion> {
        &self.filter
    }
}
impl InlineArchiveRule {
    /// Creates a new builder-style object to manufacture [`InlineArchiveRule`](crate::types::InlineArchiveRule).
    pub fn builder() -> crate::types::builders::InlineArchiveRuleBuilder {
        crate::types::builders::InlineArchiveRuleBuilder::default()
    }
}

/// A builder for [`InlineArchiveRule`](crate::types::InlineArchiveRule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InlineArchiveRuleBuilder {
    pub(crate) rule_name: ::std::option::Option<::std::string::String>,
    pub(crate) filter: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::Criterion>>,
}
impl InlineArchiveRuleBuilder {
    /// <p>The name of the rule.</p>
    /// This field is required.
    pub fn rule_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rule_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the rule.</p>
    pub fn set_rule_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rule_name = input;
        self
    }
    /// <p>The name of the rule.</p>
    pub fn get_rule_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.rule_name
    }
    /// Adds a key-value pair to `filter`.
    ///
    /// To override the contents of this collection use [`set_filter`](Self::set_filter).
    ///
    /// <p>The condition and values for a criterion.</p>
    pub fn filter(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::Criterion) -> Self {
        let mut hash_map = self.filter.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.filter = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The condition and values for a criterion.</p>
    pub fn set_filter(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::Criterion>>) -> Self {
        self.filter = input;
        self
    }
    /// <p>The condition and values for a criterion.</p>
    pub fn get_filter(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::Criterion>> {
        &self.filter
    }
    /// Consumes the builder and constructs a [`InlineArchiveRule`](crate::types::InlineArchiveRule).
    /// This method will fail if any of the following fields are not set:
    /// - [`rule_name`](crate::types::builders::InlineArchiveRuleBuilder::rule_name)
    /// - [`filter`](crate::types::builders::InlineArchiveRuleBuilder::filter)
    pub fn build(self) -> ::std::result::Result<crate::types::InlineArchiveRule, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::InlineArchiveRule {
            rule_name: self.rule_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "rule_name",
                    "rule_name was not specified but it is required when building InlineArchiveRule",
                )
            })?,
            filter: self.filter.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "filter",
                    "filter was not specified but it is required when building InlineArchiveRule",
                )
            })?,
        })
    }
}
