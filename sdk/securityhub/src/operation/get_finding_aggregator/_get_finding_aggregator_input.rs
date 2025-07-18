// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFindingAggregatorInput {
    /// <p>The ARN of the finding aggregator to return details for. To obtain the ARN, use <code>ListFindingAggregators</code>.</p>
    pub finding_aggregator_arn: ::std::option::Option<::std::string::String>,
}
impl GetFindingAggregatorInput {
    /// <p>The ARN of the finding aggregator to return details for. To obtain the ARN, use <code>ListFindingAggregators</code>.</p>
    pub fn finding_aggregator_arn(&self) -> ::std::option::Option<&str> {
        self.finding_aggregator_arn.as_deref()
    }
}
impl GetFindingAggregatorInput {
    /// Creates a new builder-style object to manufacture [`GetFindingAggregatorInput`](crate::operation::get_finding_aggregator::GetFindingAggregatorInput).
    pub fn builder() -> crate::operation::get_finding_aggregator::builders::GetFindingAggregatorInputBuilder {
        crate::operation::get_finding_aggregator::builders::GetFindingAggregatorInputBuilder::default()
    }
}

/// A builder for [`GetFindingAggregatorInput`](crate::operation::get_finding_aggregator::GetFindingAggregatorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFindingAggregatorInputBuilder {
    pub(crate) finding_aggregator_arn: ::std::option::Option<::std::string::String>,
}
impl GetFindingAggregatorInputBuilder {
    /// <p>The ARN of the finding aggregator to return details for. To obtain the ARN, use <code>ListFindingAggregators</code>.</p>
    /// This field is required.
    pub fn finding_aggregator_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.finding_aggregator_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the finding aggregator to return details for. To obtain the ARN, use <code>ListFindingAggregators</code>.</p>
    pub fn set_finding_aggregator_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.finding_aggregator_arn = input;
        self
    }
    /// <p>The ARN of the finding aggregator to return details for. To obtain the ARN, use <code>ListFindingAggregators</code>.</p>
    pub fn get_finding_aggregator_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.finding_aggregator_arn
    }
    /// Consumes the builder and constructs a [`GetFindingAggregatorInput`](crate::operation::get_finding_aggregator::GetFindingAggregatorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_finding_aggregator::GetFindingAggregatorInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_finding_aggregator::GetFindingAggregatorInput {
            finding_aggregator_arn: self.finding_aggregator_arn,
        })
    }
}
