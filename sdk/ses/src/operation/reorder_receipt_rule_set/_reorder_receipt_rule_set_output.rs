// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An empty element returned on a successful request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReorderReceiptRuleSetOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for ReorderReceiptRuleSetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ReorderReceiptRuleSetOutput {
    /// Creates a new builder-style object to manufacture [`ReorderReceiptRuleSetOutput`](crate::operation::reorder_receipt_rule_set::ReorderReceiptRuleSetOutput).
    pub fn builder() -> crate::operation::reorder_receipt_rule_set::builders::ReorderReceiptRuleSetOutputBuilder {
        crate::operation::reorder_receipt_rule_set::builders::ReorderReceiptRuleSetOutputBuilder::default()
    }
}

/// A builder for [`ReorderReceiptRuleSetOutput`](crate::operation::reorder_receipt_rule_set::ReorderReceiptRuleSetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReorderReceiptRuleSetOutputBuilder {
    _request_id: Option<String>,
}
impl ReorderReceiptRuleSetOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ReorderReceiptRuleSetOutput`](crate::operation::reorder_receipt_rule_set::ReorderReceiptRuleSetOutput).
    pub fn build(self) -> crate::operation::reorder_receipt_rule_set::ReorderReceiptRuleSetOutput {
        crate::operation::reorder_receipt_rule_set::ReorderReceiptRuleSetOutput {
            _request_id: self._request_id,
        }
    }
}
