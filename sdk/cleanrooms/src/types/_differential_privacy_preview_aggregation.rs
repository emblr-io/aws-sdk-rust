// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides an estimate of the number of aggregation functions that the member who can query can run given the epsilon and noise parameters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DifferentialPrivacyPreviewAggregation {
    /// <p>The type of aggregation function.</p>
    pub r#type: crate::types::DifferentialPrivacyAggregationType,
    /// <p>The maximum number of aggregations that the member who can query can run given the epsilon and noise parameters.</p>
    pub max_count: i32,
}
impl DifferentialPrivacyPreviewAggregation {
    /// <p>The type of aggregation function.</p>
    pub fn r#type(&self) -> &crate::types::DifferentialPrivacyAggregationType {
        &self.r#type
    }
    /// <p>The maximum number of aggregations that the member who can query can run given the epsilon and noise parameters.</p>
    pub fn max_count(&self) -> i32 {
        self.max_count
    }
}
impl DifferentialPrivacyPreviewAggregation {
    /// Creates a new builder-style object to manufacture [`DifferentialPrivacyPreviewAggregation`](crate::types::DifferentialPrivacyPreviewAggregation).
    pub fn builder() -> crate::types::builders::DifferentialPrivacyPreviewAggregationBuilder {
        crate::types::builders::DifferentialPrivacyPreviewAggregationBuilder::default()
    }
}

/// A builder for [`DifferentialPrivacyPreviewAggregation`](crate::types::DifferentialPrivacyPreviewAggregation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DifferentialPrivacyPreviewAggregationBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::DifferentialPrivacyAggregationType>,
    pub(crate) max_count: ::std::option::Option<i32>,
}
impl DifferentialPrivacyPreviewAggregationBuilder {
    /// <p>The type of aggregation function.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::DifferentialPrivacyAggregationType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of aggregation function.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::DifferentialPrivacyAggregationType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of aggregation function.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::DifferentialPrivacyAggregationType> {
        &self.r#type
    }
    /// <p>The maximum number of aggregations that the member who can query can run given the epsilon and noise parameters.</p>
    /// This field is required.
    pub fn max_count(mut self, input: i32) -> Self {
        self.max_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of aggregations that the member who can query can run given the epsilon and noise parameters.</p>
    pub fn set_max_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_count = input;
        self
    }
    /// <p>The maximum number of aggregations that the member who can query can run given the epsilon and noise parameters.</p>
    pub fn get_max_count(&self) -> &::std::option::Option<i32> {
        &self.max_count
    }
    /// Consumes the builder and constructs a [`DifferentialPrivacyPreviewAggregation`](crate::types::DifferentialPrivacyPreviewAggregation).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::DifferentialPrivacyPreviewAggregationBuilder::type)
    /// - [`max_count`](crate::types::builders::DifferentialPrivacyPreviewAggregationBuilder::max_count)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::DifferentialPrivacyPreviewAggregation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DifferentialPrivacyPreviewAggregation {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building DifferentialPrivacyPreviewAggregation",
                )
            })?,
            max_count: self.max_count.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "max_count",
                    "max_count was not specified but it is required when building DifferentialPrivacyPreviewAggregation",
                )
            })?,
        })
    }
}
