// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetComplianceDetailsByConfigRuleInput {
    /// <p>The name of the Config rule for which you want compliance information.</p>
    pub config_rule_name: ::std::option::Option<::std::string::String>,
    /// <p>Filters the results by compliance.</p>
    /// <p><code>INSUFFICIENT_DATA</code> is a valid <code>ComplianceType</code> that is returned when an Config rule cannot be evaluated. However, <code>INSUFFICIENT_DATA</code> cannot be used as a <code>ComplianceType</code> for filtering results.</p>
    pub compliance_types: ::std::option::Option<::std::vec::Vec<crate::types::ComplianceType>>,
    /// <p>The maximum number of evaluation results returned on each page. The default is 10. You cannot specify a number greater than 100. If you specify 0, Config uses the default.</p>
    pub limit: ::std::option::Option<i32>,
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetComplianceDetailsByConfigRuleInput {
    /// <p>The name of the Config rule for which you want compliance information.</p>
    pub fn config_rule_name(&self) -> ::std::option::Option<&str> {
        self.config_rule_name.as_deref()
    }
    /// <p>Filters the results by compliance.</p>
    /// <p><code>INSUFFICIENT_DATA</code> is a valid <code>ComplianceType</code> that is returned when an Config rule cannot be evaluated. However, <code>INSUFFICIENT_DATA</code> cannot be used as a <code>ComplianceType</code> for filtering results.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.compliance_types.is_none()`.
    pub fn compliance_types(&self) -> &[crate::types::ComplianceType] {
        self.compliance_types.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of evaluation results returned on each page. The default is 10. You cannot specify a number greater than 100. If you specify 0, Config uses the default.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
    /// <p>The <code>nextToken</code> string returned on a previous page that you use to get the next page of results in a paginated response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetComplianceDetailsByConfigRuleInput {
    /// Creates a new builder-style object to manufacture [`GetComplianceDetailsByConfigRuleInput`](crate::operation::get_compliance_details_by_config_rule::GetComplianceDetailsByConfigRuleInput).
    pub fn builder() -> crate::operation::get_compliance_details_by_config_rule::builders::GetComplianceDetailsByConfigRuleInputBuilder {
        crate::operation::get_compliance_details_by_config_rule::builders::GetComplianceDetailsByConfigRuleInputBuilder::default()
    }
}

/// A builder for [`GetComplianceDetailsByConfigRuleInput`](crate::operation::get_compliance_details_by_config_rule::GetComplianceDetailsByConfigRuleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetComplianceDetailsByConfigRuleInputBuilder {
    pub(crate) config_rule_name: ::std::option::Option<::std::string::String>,
    pub(crate) compliance_types: ::std::option::Option<::std::vec::Vec<crate::types::ComplianceType>>,
    pub(crate) limit: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetComplianceDetailsByConfigRuleInputBuilder {
    /// <p>The name of the Config rule for which you want compliance information.</p>
    /// This field is required.
    pub fn config_rule_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.config_rule_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Config rule for which you want compliance information.</p>
    pub fn set_config_rule_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.config_rule_name = input;
        self
    }
    /// <p>The name of the Config rule for which you want compliance information.</p>
    pub fn get_config_rule_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.config_rule_name
    }
    /// Appends an item to `compliance_types`.
    ///
    /// To override the contents of this collection use [`set_compliance_types`](Self::set_compliance_types).
    ///
    /// <p>Filters the results by compliance.</p>
    /// <p><code>INSUFFICIENT_DATA</code> is a valid <code>ComplianceType</code> that is returned when an Config rule cannot be evaluated. However, <code>INSUFFICIENT_DATA</code> cannot be used as a <code>ComplianceType</code> for filtering results.</p>
    pub fn compliance_types(mut self, input: crate::types::ComplianceType) -> Self {
        let mut v = self.compliance_types.unwrap_or_default();
        v.push(input);
        self.compliance_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters the results by compliance.</p>
    /// <p><code>INSUFFICIENT_DATA</code> is a valid <code>ComplianceType</code> that is returned when an Config rule cannot be evaluated. However, <code>INSUFFICIENT_DATA</code> cannot be used as a <code>ComplianceType</code> for filtering results.</p>
    pub fn set_compliance_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ComplianceType>>) -> Self {
        self.compliance_types = input;
        self
    }
    /// <p>Filters the results by compliance.</p>
    /// <p><code>INSUFFICIENT_DATA</code> is a valid <code>ComplianceType</code> that is returned when an Config rule cannot be evaluated. However, <code>INSUFFICIENT_DATA</code> cannot be used as a <code>ComplianceType</code> for filtering results.</p>
    pub fn get_compliance_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ComplianceType>> {
        &self.compliance_types
    }
    /// <p>The maximum number of evaluation results returned on each page. The default is 10. You cannot specify a number greater than 100. If you specify 0, Config uses the default.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of evaluation results returned on each page. The default is 10. You cannot specify a number greater than 100. If you specify 0, Config uses the default.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The maximum number of evaluation results returned on each page. The default is 10. You cannot specify a number greater than 100. If you specify 0, Config uses the default.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
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
    /// Consumes the builder and constructs a [`GetComplianceDetailsByConfigRuleInput`](crate::operation::get_compliance_details_by_config_rule::GetComplianceDetailsByConfigRuleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_compliance_details_by_config_rule::GetComplianceDetailsByConfigRuleInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_compliance_details_by_config_rule::GetComplianceDetailsByConfigRuleInput {
                config_rule_name: self.config_rule_name,
                compliance_types: self.compliance_types,
                limit: self.limit,
                next_token: self.next_token,
            },
        )
    }
}
