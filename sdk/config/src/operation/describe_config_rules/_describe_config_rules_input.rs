// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeConfigRulesInput {
    /// <p>The names of the Config rules for which you want details. If you do not specify any names, Config returns details for all your rules.</p>
    pub config_rule_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Returns a list of Detective or Proactive Config rules. By default, this API returns an unfiltered list. For more information on Detective or Proactive Config rules, see <a href="https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config-rules.html"> <b>Evaluation Mode</b> </a> in the <i>Config Developer Guide</i>.</p>
    pub filters: ::std::option::Option<crate::types::DescribeConfigRulesFilters>,
}
impl DescribeConfigRulesInput {
    /// <p>The names of the Config rules for which you want details. If you do not specify any names, Config returns details for all your rules.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.config_rule_names.is_none()`.
    pub fn config_rule_names(&self) -> &[::std::string::String] {
        self.config_rule_names.as_deref().unwrap_or_default()
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Returns a list of Detective or Proactive Config rules. By default, this API returns an unfiltered list. For more information on Detective or Proactive Config rules, see <a href="https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config-rules.html"> <b>Evaluation Mode</b> </a> in the <i>Config Developer Guide</i>.</p>
    pub fn filters(&self) -> ::std::option::Option<&crate::types::DescribeConfigRulesFilters> {
        self.filters.as_ref()
    }
}
impl DescribeConfigRulesInput {
    /// Creates a new builder-style object to manufacture [`DescribeConfigRulesInput`](crate::operation::describe_config_rules::DescribeConfigRulesInput).
    pub fn builder() -> crate::operation::describe_config_rules::builders::DescribeConfigRulesInputBuilder {
        crate::operation::describe_config_rules::builders::DescribeConfigRulesInputBuilder::default()
    }
}

/// A builder for [`DescribeConfigRulesInput`](crate::operation::describe_config_rules::DescribeConfigRulesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeConfigRulesInputBuilder {
    pub(crate) config_rule_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<crate::types::DescribeConfigRulesFilters>,
}
impl DescribeConfigRulesInputBuilder {
    /// Appends an item to `config_rule_names`.
    ///
    /// To override the contents of this collection use [`set_config_rule_names`](Self::set_config_rule_names).
    ///
    /// <p>The names of the Config rules for which you want details. If you do not specify any names, Config returns details for all your rules.</p>
    pub fn config_rule_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.config_rule_names.unwrap_or_default();
        v.push(input.into());
        self.config_rule_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The names of the Config rules for which you want details. If you do not specify any names, Config returns details for all your rules.</p>
    pub fn set_config_rule_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.config_rule_names = input;
        self
    }
    /// <p>The names of the Config rules for which you want details. If you do not specify any names, Config returns details for all your rules.</p>
    pub fn get_config_rule_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.config_rule_names
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Returns a list of Detective or Proactive Config rules. By default, this API returns an unfiltered list. For more information on Detective or Proactive Config rules, see <a href="https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config-rules.html"> <b>Evaluation Mode</b> </a> in the <i>Config Developer Guide</i>.</p>
    pub fn filters(mut self, input: crate::types::DescribeConfigRulesFilters) -> Self {
        self.filters = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns a list of Detective or Proactive Config rules. By default, this API returns an unfiltered list. For more information on Detective or Proactive Config rules, see <a href="https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config-rules.html"> <b>Evaluation Mode</b> </a> in the <i>Config Developer Guide</i>.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<crate::types::DescribeConfigRulesFilters>) -> Self {
        self.filters = input;
        self
    }
    /// <p>Returns a list of Detective or Proactive Config rules. By default, this API returns an unfiltered list. For more information on Detective or Proactive Config rules, see <a href="https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config-rules.html"> <b>Evaluation Mode</b> </a> in the <i>Config Developer Guide</i>.</p>
    pub fn get_filters(&self) -> &::std::option::Option<crate::types::DescribeConfigRulesFilters> {
        &self.filters
    }
    /// Consumes the builder and constructs a [`DescribeConfigRulesInput`](crate::operation::describe_config_rules::DescribeConfigRulesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_config_rules::DescribeConfigRulesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_config_rules::DescribeConfigRulesInput {
            config_rule_names: self.config_rule_names,
            next_token: self.next_token,
            filters: self.filters,
        })
    }
}
