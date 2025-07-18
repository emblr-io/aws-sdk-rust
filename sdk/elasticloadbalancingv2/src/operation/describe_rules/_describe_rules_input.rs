// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeRulesInput {
    /// <p>The Amazon Resource Name (ARN) of the listener.</p>
    pub listener_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Names (ARN) of the rules.</p>
    pub rule_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The marker for the next set of results. (You received this marker from a previous call.)</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return with this call.</p>
    pub page_size: ::std::option::Option<i32>,
}
impl DescribeRulesInput {
    /// <p>The Amazon Resource Name (ARN) of the listener.</p>
    pub fn listener_arn(&self) -> ::std::option::Option<&str> {
        self.listener_arn.as_deref()
    }
    /// <p>The Amazon Resource Names (ARN) of the rules.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rule_arns.is_none()`.
    pub fn rule_arns(&self) -> &[::std::string::String] {
        self.rule_arns.as_deref().unwrap_or_default()
    }
    /// <p>The marker for the next set of results. (You received this marker from a previous call.)</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>The maximum number of results to return with this call.</p>
    pub fn page_size(&self) -> ::std::option::Option<i32> {
        self.page_size
    }
}
impl DescribeRulesInput {
    /// Creates a new builder-style object to manufacture [`DescribeRulesInput`](crate::operation::describe_rules::DescribeRulesInput).
    pub fn builder() -> crate::operation::describe_rules::builders::DescribeRulesInputBuilder {
        crate::operation::describe_rules::builders::DescribeRulesInputBuilder::default()
    }
}

/// A builder for [`DescribeRulesInput`](crate::operation::describe_rules::DescribeRulesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeRulesInputBuilder {
    pub(crate) listener_arn: ::std::option::Option<::std::string::String>,
    pub(crate) rule_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) page_size: ::std::option::Option<i32>,
}
impl DescribeRulesInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the listener.</p>
    pub fn listener_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.listener_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the listener.</p>
    pub fn set_listener_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.listener_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the listener.</p>
    pub fn get_listener_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.listener_arn
    }
    /// Appends an item to `rule_arns`.
    ///
    /// To override the contents of this collection use [`set_rule_arns`](Self::set_rule_arns).
    ///
    /// <p>The Amazon Resource Names (ARN) of the rules.</p>
    pub fn rule_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.rule_arns.unwrap_or_default();
        v.push(input.into());
        self.rule_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Resource Names (ARN) of the rules.</p>
    pub fn set_rule_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.rule_arns = input;
        self
    }
    /// <p>The Amazon Resource Names (ARN) of the rules.</p>
    pub fn get_rule_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.rule_arns
    }
    /// <p>The marker for the next set of results. (You received this marker from a previous call.)</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The marker for the next set of results. (You received this marker from a previous call.)</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>The marker for the next set of results. (You received this marker from a previous call.)</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>The maximum number of results to return with this call.</p>
    pub fn page_size(mut self, input: i32) -> Self {
        self.page_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return with this call.</p>
    pub fn set_page_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.page_size = input;
        self
    }
    /// <p>The maximum number of results to return with this call.</p>
    pub fn get_page_size(&self) -> &::std::option::Option<i32> {
        &self.page_size
    }
    /// Consumes the builder and constructs a [`DescribeRulesInput`](crate::operation::describe_rules::DescribeRulesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_rules::DescribeRulesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_rules::DescribeRulesInput {
            listener_arn: self.listener_arn,
            rule_arns: self.rule_arns,
            marker: self.marker,
            page_size: self.page_size,
        })
    }
}
