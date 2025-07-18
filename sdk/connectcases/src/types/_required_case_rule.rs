// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Required rule type, used to indicate whether a field is required. In the Amazon Connect admin website, case rules are known as <i>case field conditions</i>. For more information about case field conditions, see <a href="https://docs.aws.amazon.com/connect/latest/adminguide/case-field-conditions.html">Add case field conditions to a case template</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RequiredCaseRule {
    /// <p>The value of the rule (that is, whether the field is required) should none of the conditions evaluate to true.</p>
    pub default_value: bool,
    /// <p>List of conditions for the required rule; the first condition to evaluate to true dictates the value of the rule.</p>
    pub conditions: ::std::vec::Vec<crate::types::BooleanCondition>,
}
impl RequiredCaseRule {
    /// <p>The value of the rule (that is, whether the field is required) should none of the conditions evaluate to true.</p>
    pub fn default_value(&self) -> bool {
        self.default_value
    }
    /// <p>List of conditions for the required rule; the first condition to evaluate to true dictates the value of the rule.</p>
    pub fn conditions(&self) -> &[crate::types::BooleanCondition] {
        use std::ops::Deref;
        self.conditions.deref()
    }
}
impl RequiredCaseRule {
    /// Creates a new builder-style object to manufacture [`RequiredCaseRule`](crate::types::RequiredCaseRule).
    pub fn builder() -> crate::types::builders::RequiredCaseRuleBuilder {
        crate::types::builders::RequiredCaseRuleBuilder::default()
    }
}

/// A builder for [`RequiredCaseRule`](crate::types::RequiredCaseRule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RequiredCaseRuleBuilder {
    pub(crate) default_value: ::std::option::Option<bool>,
    pub(crate) conditions: ::std::option::Option<::std::vec::Vec<crate::types::BooleanCondition>>,
}
impl RequiredCaseRuleBuilder {
    /// <p>The value of the rule (that is, whether the field is required) should none of the conditions evaluate to true.</p>
    /// This field is required.
    pub fn default_value(mut self, input: bool) -> Self {
        self.default_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value of the rule (that is, whether the field is required) should none of the conditions evaluate to true.</p>
    pub fn set_default_value(mut self, input: ::std::option::Option<bool>) -> Self {
        self.default_value = input;
        self
    }
    /// <p>The value of the rule (that is, whether the field is required) should none of the conditions evaluate to true.</p>
    pub fn get_default_value(&self) -> &::std::option::Option<bool> {
        &self.default_value
    }
    /// Appends an item to `conditions`.
    ///
    /// To override the contents of this collection use [`set_conditions`](Self::set_conditions).
    ///
    /// <p>List of conditions for the required rule; the first condition to evaluate to true dictates the value of the rule.</p>
    pub fn conditions(mut self, input: crate::types::BooleanCondition) -> Self {
        let mut v = self.conditions.unwrap_or_default();
        v.push(input);
        self.conditions = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of conditions for the required rule; the first condition to evaluate to true dictates the value of the rule.</p>
    pub fn set_conditions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BooleanCondition>>) -> Self {
        self.conditions = input;
        self
    }
    /// <p>List of conditions for the required rule; the first condition to evaluate to true dictates the value of the rule.</p>
    pub fn get_conditions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BooleanCondition>> {
        &self.conditions
    }
    /// Consumes the builder and constructs a [`RequiredCaseRule`](crate::types::RequiredCaseRule).
    /// This method will fail if any of the following fields are not set:
    /// - [`default_value`](crate::types::builders::RequiredCaseRuleBuilder::default_value)
    /// - [`conditions`](crate::types::builders::RequiredCaseRuleBuilder::conditions)
    pub fn build(self) -> ::std::result::Result<crate::types::RequiredCaseRule, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RequiredCaseRule {
            default_value: self.default_value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "default_value",
                    "default_value was not specified but it is required when building RequiredCaseRule",
                )
            })?,
            conditions: self.conditions.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "conditions",
                    "conditions was not specified but it is required when building RequiredCaseRule",
                )
            })?,
        })
    }
}
