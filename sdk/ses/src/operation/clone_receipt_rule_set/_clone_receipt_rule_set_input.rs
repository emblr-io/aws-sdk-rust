// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a request to create a receipt rule set by cloning an existing one. You use receipt rule sets to receive email with Amazon SES. For more information, see the <a href="https://docs.aws.amazon.com/ses/latest/dg/receiving-email-concepts.html">Amazon SES Developer Guide</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloneReceiptRuleSetInput {
    /// <p>The name of the rule set to create. The name must meet the following requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only ASCII letters (a-z, A-Z), numbers (0-9), underscores (_), or dashes (-).</p></li>
    /// <li>
    /// <p>Start and end with a letter or number.</p></li>
    /// <li>
    /// <p>Contain 64 characters or fewer.</p></li>
    /// </ul>
    pub rule_set_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the rule set to clone.</p>
    pub original_rule_set_name: ::std::option::Option<::std::string::String>,
}
impl CloneReceiptRuleSetInput {
    /// <p>The name of the rule set to create. The name must meet the following requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only ASCII letters (a-z, A-Z), numbers (0-9), underscores (_), or dashes (-).</p></li>
    /// <li>
    /// <p>Start and end with a letter or number.</p></li>
    /// <li>
    /// <p>Contain 64 characters or fewer.</p></li>
    /// </ul>
    pub fn rule_set_name(&self) -> ::std::option::Option<&str> {
        self.rule_set_name.as_deref()
    }
    /// <p>The name of the rule set to clone.</p>
    pub fn original_rule_set_name(&self) -> ::std::option::Option<&str> {
        self.original_rule_set_name.as_deref()
    }
}
impl CloneReceiptRuleSetInput {
    /// Creates a new builder-style object to manufacture [`CloneReceiptRuleSetInput`](crate::operation::clone_receipt_rule_set::CloneReceiptRuleSetInput).
    pub fn builder() -> crate::operation::clone_receipt_rule_set::builders::CloneReceiptRuleSetInputBuilder {
        crate::operation::clone_receipt_rule_set::builders::CloneReceiptRuleSetInputBuilder::default()
    }
}

/// A builder for [`CloneReceiptRuleSetInput`](crate::operation::clone_receipt_rule_set::CloneReceiptRuleSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloneReceiptRuleSetInputBuilder {
    pub(crate) rule_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) original_rule_set_name: ::std::option::Option<::std::string::String>,
}
impl CloneReceiptRuleSetInputBuilder {
    /// <p>The name of the rule set to create. The name must meet the following requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only ASCII letters (a-z, A-Z), numbers (0-9), underscores (_), or dashes (-).</p></li>
    /// <li>
    /// <p>Start and end with a letter or number.</p></li>
    /// <li>
    /// <p>Contain 64 characters or fewer.</p></li>
    /// </ul>
    /// This field is required.
    pub fn rule_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rule_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the rule set to create. The name must meet the following requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only ASCII letters (a-z, A-Z), numbers (0-9), underscores (_), or dashes (-).</p></li>
    /// <li>
    /// <p>Start and end with a letter or number.</p></li>
    /// <li>
    /// <p>Contain 64 characters or fewer.</p></li>
    /// </ul>
    pub fn set_rule_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rule_set_name = input;
        self
    }
    /// <p>The name of the rule set to create. The name must meet the following requirements:</p>
    /// <ul>
    /// <li>
    /// <p>Contain only ASCII letters (a-z, A-Z), numbers (0-9), underscores (_), or dashes (-).</p></li>
    /// <li>
    /// <p>Start and end with a letter or number.</p></li>
    /// <li>
    /// <p>Contain 64 characters or fewer.</p></li>
    /// </ul>
    pub fn get_rule_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.rule_set_name
    }
    /// <p>The name of the rule set to clone.</p>
    /// This field is required.
    pub fn original_rule_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.original_rule_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the rule set to clone.</p>
    pub fn set_original_rule_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.original_rule_set_name = input;
        self
    }
    /// <p>The name of the rule set to clone.</p>
    pub fn get_original_rule_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.original_rule_set_name
    }
    /// Consumes the builder and constructs a [`CloneReceiptRuleSetInput`](crate::operation::clone_receipt_rule_set::CloneReceiptRuleSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::clone_receipt_rule_set::CloneReceiptRuleSetInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::clone_receipt_rule_set::CloneReceiptRuleSetInput {
            rule_set_name: self.rule_set_name,
            original_rule_set_name: self.original_rule_set_name,
        })
    }
}
