// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListRulesOutput {
    /// <p>Summary information about a rule.</p>
    pub rule_summary_list: ::std::vec::Vec<crate::types::RuleSummary>,
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRulesOutput {
    /// <p>Summary information about a rule.</p>
    pub fn rule_summary_list(&self) -> &[crate::types::RuleSummary] {
        use std::ops::Deref;
        self.rule_summary_list.deref()
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListRulesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListRulesOutput {
    /// Creates a new builder-style object to manufacture [`ListRulesOutput`](crate::operation::list_rules::ListRulesOutput).
    pub fn builder() -> crate::operation::list_rules::builders::ListRulesOutputBuilder {
        crate::operation::list_rules::builders::ListRulesOutputBuilder::default()
    }
}

/// A builder for [`ListRulesOutput`](crate::operation::list_rules::ListRulesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListRulesOutputBuilder {
    pub(crate) rule_summary_list: ::std::option::Option<::std::vec::Vec<crate::types::RuleSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListRulesOutputBuilder {
    /// Appends an item to `rule_summary_list`.
    ///
    /// To override the contents of this collection use [`set_rule_summary_list`](Self::set_rule_summary_list).
    ///
    /// <p>Summary information about a rule.</p>
    pub fn rule_summary_list(mut self, input: crate::types::RuleSummary) -> Self {
        let mut v = self.rule_summary_list.unwrap_or_default();
        v.push(input);
        self.rule_summary_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>Summary information about a rule.</p>
    pub fn set_rule_summary_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RuleSummary>>) -> Self {
        self.rule_summary_list = input;
        self
    }
    /// <p>Summary information about a rule.</p>
    pub fn get_rule_summary_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RuleSummary>> {
        &self.rule_summary_list
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListRulesOutput`](crate::operation::list_rules::ListRulesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`rule_summary_list`](crate::operation::list_rules::builders::ListRulesOutputBuilder::rule_summary_list)
    pub fn build(self) -> ::std::result::Result<crate::operation::list_rules::ListRulesOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_rules::ListRulesOutput {
            rule_summary_list: self.rule_summary_list.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "rule_summary_list",
                    "rule_summary_list was not specified but it is required when building ListRulesOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
