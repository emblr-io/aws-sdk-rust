// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a request to set a receipt rule set as the active receipt rule set. You use receipt rule sets to receive email with Amazon SES. For more information, see the <a href="https://docs.aws.amazon.com/ses/latest/dg/receiving-email-concepts.html">Amazon SES Developer Guide</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SetActiveReceiptRuleSetInput {
    /// <p>The name of the receipt rule set to make active. Setting this value to null disables all email receiving.</p>
    pub rule_set_name: ::std::option::Option<::std::string::String>,
}
impl SetActiveReceiptRuleSetInput {
    /// <p>The name of the receipt rule set to make active. Setting this value to null disables all email receiving.</p>
    pub fn rule_set_name(&self) -> ::std::option::Option<&str> {
        self.rule_set_name.as_deref()
    }
}
impl SetActiveReceiptRuleSetInput {
    /// Creates a new builder-style object to manufacture [`SetActiveReceiptRuleSetInput`](crate::operation::set_active_receipt_rule_set::SetActiveReceiptRuleSetInput).
    pub fn builder() -> crate::operation::set_active_receipt_rule_set::builders::SetActiveReceiptRuleSetInputBuilder {
        crate::operation::set_active_receipt_rule_set::builders::SetActiveReceiptRuleSetInputBuilder::default()
    }
}

/// A builder for [`SetActiveReceiptRuleSetInput`](crate::operation::set_active_receipt_rule_set::SetActiveReceiptRuleSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SetActiveReceiptRuleSetInputBuilder {
    pub(crate) rule_set_name: ::std::option::Option<::std::string::String>,
}
impl SetActiveReceiptRuleSetInputBuilder {
    /// <p>The name of the receipt rule set to make active. Setting this value to null disables all email receiving.</p>
    pub fn rule_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rule_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the receipt rule set to make active. Setting this value to null disables all email receiving.</p>
    pub fn set_rule_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rule_set_name = input;
        self
    }
    /// <p>The name of the receipt rule set to make active. Setting this value to null disables all email receiving.</p>
    pub fn get_rule_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.rule_set_name
    }
    /// Consumes the builder and constructs a [`SetActiveReceiptRuleSetInput`](crate::operation::set_active_receipt_rule_set::SetActiveReceiptRuleSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::set_active_receipt_rule_set::SetActiveReceiptRuleSetInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::set_active_receipt_rule_set::SetActiveReceiptRuleSetInput {
            rule_set_name: self.rule_set_name,
        })
    }
}
