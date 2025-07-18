// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeConfigRuleEvaluationStatusInput {
    /// <p>The name of the Config managed rules for which you want status information. If you do not specify any names, Config returns status information for all Config managed rules that you use.</p>
    pub config_rule_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The number of rule evaluation results that you want returned.</p>
    /// <p>This parameter is required if the rule limit for your account is more than the default of 1000 rules.</p>
    /// <p>For information about requesting a rule limit increase, see <a href="http://docs.aws.amazon.com/general/latest/gr/aws_service_limits.html#limits_config">Config Limits</a> in the <i>Amazon Web Services General Reference Guide</i>.</p>
    pub limit: ::std::option::Option<i32>,
}
impl DescribeConfigRuleEvaluationStatusInput {
    /// <p>The name of the Config managed rules for which you want status information. If you do not specify any names, Config returns status information for all Config managed rules that you use.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.config_rule_names.is_none()`.
    pub fn config_rule_names(&self) -> &[::std::string::String] {
        self.config_rule_names.as_deref().unwrap_or_default()
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The number of rule evaluation results that you want returned.</p>
    /// <p>This parameter is required if the rule limit for your account is more than the default of 1000 rules.</p>
    /// <p>For information about requesting a rule limit increase, see <a href="http://docs.aws.amazon.com/general/latest/gr/aws_service_limits.html#limits_config">Config Limits</a> in the <i>Amazon Web Services General Reference Guide</i>.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
}
impl DescribeConfigRuleEvaluationStatusInput {
    /// Creates a new builder-style object to manufacture [`DescribeConfigRuleEvaluationStatusInput`](crate::operation::describe_config_rule_evaluation_status::DescribeConfigRuleEvaluationStatusInput).
    pub fn builder() -> crate::operation::describe_config_rule_evaluation_status::builders::DescribeConfigRuleEvaluationStatusInputBuilder {
        crate::operation::describe_config_rule_evaluation_status::builders::DescribeConfigRuleEvaluationStatusInputBuilder::default()
    }
}

/// A builder for [`DescribeConfigRuleEvaluationStatusInput`](crate::operation::describe_config_rule_evaluation_status::DescribeConfigRuleEvaluationStatusInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeConfigRuleEvaluationStatusInputBuilder {
    pub(crate) config_rule_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
}
impl DescribeConfigRuleEvaluationStatusInputBuilder {
    /// Appends an item to `config_rule_names`.
    ///
    /// To override the contents of this collection use [`set_config_rule_names`](Self::set_config_rule_names).
    ///
    /// <p>The name of the Config managed rules for which you want status information. If you do not specify any names, Config returns status information for all Config managed rules that you use.</p>
    pub fn config_rule_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.config_rule_names.unwrap_or_default();
        v.push(input.into());
        self.config_rule_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>The name of the Config managed rules for which you want status information. If you do not specify any names, Config returns status information for all Config managed rules that you use.</p>
    pub fn set_config_rule_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.config_rule_names = input;
        self
    }
    /// <p>The name of the Config managed rules for which you want status information. If you do not specify any names, Config returns status information for all Config managed rules that you use.</p>
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
    /// <p>The number of rule evaluation results that you want returned.</p>
    /// <p>This parameter is required if the rule limit for your account is more than the default of 1000 rules.</p>
    /// <p>For information about requesting a rule limit increase, see <a href="http://docs.aws.amazon.com/general/latest/gr/aws_service_limits.html#limits_config">Config Limits</a> in the <i>Amazon Web Services General Reference Guide</i>.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of rule evaluation results that you want returned.</p>
    /// <p>This parameter is required if the rule limit for your account is more than the default of 1000 rules.</p>
    /// <p>For information about requesting a rule limit increase, see <a href="http://docs.aws.amazon.com/general/latest/gr/aws_service_limits.html#limits_config">Config Limits</a> in the <i>Amazon Web Services General Reference Guide</i>.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The number of rule evaluation results that you want returned.</p>
    /// <p>This parameter is required if the rule limit for your account is more than the default of 1000 rules.</p>
    /// <p>For information about requesting a rule limit increase, see <a href="http://docs.aws.amazon.com/general/latest/gr/aws_service_limits.html#limits_config">Config Limits</a> in the <i>Amazon Web Services General Reference Guide</i>.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// Consumes the builder and constructs a [`DescribeConfigRuleEvaluationStatusInput`](crate::operation::describe_config_rule_evaluation_status::DescribeConfigRuleEvaluationStatusInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_config_rule_evaluation_status::DescribeConfigRuleEvaluationStatusInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_config_rule_evaluation_status::DescribeConfigRuleEvaluationStatusInput {
                config_rule_names: self.config_rule_names,
                next_token: self.next_token,
                limit: self.limit,
            },
        )
    }
}
