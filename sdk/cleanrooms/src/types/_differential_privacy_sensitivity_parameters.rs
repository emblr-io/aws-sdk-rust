// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the sensitivity parameters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DifferentialPrivacySensitivityParameters {
    /// <p>The type of aggregation function that was run.</p>
    pub aggregation_type: crate::types::DifferentialPrivacyAggregationType,
    /// <p>The aggregation expression that was run.</p>
    pub aggregation_expression: ::std::string::String,
    /// <p>The maximum number of rows contributed by a user in a SQL query.</p>
    pub user_contribution_limit: i32,
    /// <p>The lower bound of the aggregation expression.</p>
    pub min_column_value: ::std::option::Option<f32>,
    /// <p>The upper bound of the aggregation expression.</p>
    pub max_column_value: ::std::option::Option<f32>,
}
impl DifferentialPrivacySensitivityParameters {
    /// <p>The type of aggregation function that was run.</p>
    pub fn aggregation_type(&self) -> &crate::types::DifferentialPrivacyAggregationType {
        &self.aggregation_type
    }
    /// <p>The aggregation expression that was run.</p>
    pub fn aggregation_expression(&self) -> &str {
        use std::ops::Deref;
        self.aggregation_expression.deref()
    }
    /// <p>The maximum number of rows contributed by a user in a SQL query.</p>
    pub fn user_contribution_limit(&self) -> i32 {
        self.user_contribution_limit
    }
    /// <p>The lower bound of the aggregation expression.</p>
    pub fn min_column_value(&self) -> ::std::option::Option<f32> {
        self.min_column_value
    }
    /// <p>The upper bound of the aggregation expression.</p>
    pub fn max_column_value(&self) -> ::std::option::Option<f32> {
        self.max_column_value
    }
}
impl DifferentialPrivacySensitivityParameters {
    /// Creates a new builder-style object to manufacture [`DifferentialPrivacySensitivityParameters`](crate::types::DifferentialPrivacySensitivityParameters).
    pub fn builder() -> crate::types::builders::DifferentialPrivacySensitivityParametersBuilder {
        crate::types::builders::DifferentialPrivacySensitivityParametersBuilder::default()
    }
}

/// A builder for [`DifferentialPrivacySensitivityParameters`](crate::types::DifferentialPrivacySensitivityParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DifferentialPrivacySensitivityParametersBuilder {
    pub(crate) aggregation_type: ::std::option::Option<crate::types::DifferentialPrivacyAggregationType>,
    pub(crate) aggregation_expression: ::std::option::Option<::std::string::String>,
    pub(crate) user_contribution_limit: ::std::option::Option<i32>,
    pub(crate) min_column_value: ::std::option::Option<f32>,
    pub(crate) max_column_value: ::std::option::Option<f32>,
}
impl DifferentialPrivacySensitivityParametersBuilder {
    /// <p>The type of aggregation function that was run.</p>
    /// This field is required.
    pub fn aggregation_type(mut self, input: crate::types::DifferentialPrivacyAggregationType) -> Self {
        self.aggregation_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of aggregation function that was run.</p>
    pub fn set_aggregation_type(mut self, input: ::std::option::Option<crate::types::DifferentialPrivacyAggregationType>) -> Self {
        self.aggregation_type = input;
        self
    }
    /// <p>The type of aggregation function that was run.</p>
    pub fn get_aggregation_type(&self) -> &::std::option::Option<crate::types::DifferentialPrivacyAggregationType> {
        &self.aggregation_type
    }
    /// <p>The aggregation expression that was run.</p>
    /// This field is required.
    pub fn aggregation_expression(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aggregation_expression = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The aggregation expression that was run.</p>
    pub fn set_aggregation_expression(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aggregation_expression = input;
        self
    }
    /// <p>The aggregation expression that was run.</p>
    pub fn get_aggregation_expression(&self) -> &::std::option::Option<::std::string::String> {
        &self.aggregation_expression
    }
    /// <p>The maximum number of rows contributed by a user in a SQL query.</p>
    /// This field is required.
    pub fn user_contribution_limit(mut self, input: i32) -> Self {
        self.user_contribution_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of rows contributed by a user in a SQL query.</p>
    pub fn set_user_contribution_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.user_contribution_limit = input;
        self
    }
    /// <p>The maximum number of rows contributed by a user in a SQL query.</p>
    pub fn get_user_contribution_limit(&self) -> &::std::option::Option<i32> {
        &self.user_contribution_limit
    }
    /// <p>The lower bound of the aggregation expression.</p>
    pub fn min_column_value(mut self, input: f32) -> Self {
        self.min_column_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The lower bound of the aggregation expression.</p>
    pub fn set_min_column_value(mut self, input: ::std::option::Option<f32>) -> Self {
        self.min_column_value = input;
        self
    }
    /// <p>The lower bound of the aggregation expression.</p>
    pub fn get_min_column_value(&self) -> &::std::option::Option<f32> {
        &self.min_column_value
    }
    /// <p>The upper bound of the aggregation expression.</p>
    pub fn max_column_value(mut self, input: f32) -> Self {
        self.max_column_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The upper bound of the aggregation expression.</p>
    pub fn set_max_column_value(mut self, input: ::std::option::Option<f32>) -> Self {
        self.max_column_value = input;
        self
    }
    /// <p>The upper bound of the aggregation expression.</p>
    pub fn get_max_column_value(&self) -> &::std::option::Option<f32> {
        &self.max_column_value
    }
    /// Consumes the builder and constructs a [`DifferentialPrivacySensitivityParameters`](crate::types::DifferentialPrivacySensitivityParameters).
    /// This method will fail if any of the following fields are not set:
    /// - [`aggregation_type`](crate::types::builders::DifferentialPrivacySensitivityParametersBuilder::aggregation_type)
    /// - [`aggregation_expression`](crate::types::builders::DifferentialPrivacySensitivityParametersBuilder::aggregation_expression)
    /// - [`user_contribution_limit`](crate::types::builders::DifferentialPrivacySensitivityParametersBuilder::user_contribution_limit)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::DifferentialPrivacySensitivityParameters, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DifferentialPrivacySensitivityParameters {
            aggregation_type: self.aggregation_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "aggregation_type",
                    "aggregation_type was not specified but it is required when building DifferentialPrivacySensitivityParameters",
                )
            })?,
            aggregation_expression: self.aggregation_expression.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "aggregation_expression",
                    "aggregation_expression was not specified but it is required when building DifferentialPrivacySensitivityParameters",
                )
            })?,
            user_contribution_limit: self.user_contribution_limit.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "user_contribution_limit",
                    "user_contribution_limit was not specified but it is required when building DifferentialPrivacySensitivityParameters",
                )
            })?,
            min_column_value: self.min_column_value,
            max_column_value: self.max_column_value,
        })
    }
}
