// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains metadata about a label detection request, including the SortBy and AggregateBy options.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLabelDetectionRequestMetadata {
    /// <p>The sorting method chosen for a GetLabelDetection request.</p>
    pub sort_by: ::std::option::Option<crate::types::LabelDetectionSortBy>,
    /// <p>The aggregation method chosen for a GetLabelDetection request.</p>
    pub aggregate_by: ::std::option::Option<crate::types::LabelDetectionAggregateBy>,
}
impl GetLabelDetectionRequestMetadata {
    /// <p>The sorting method chosen for a GetLabelDetection request.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::LabelDetectionSortBy> {
        self.sort_by.as_ref()
    }
    /// <p>The aggregation method chosen for a GetLabelDetection request.</p>
    pub fn aggregate_by(&self) -> ::std::option::Option<&crate::types::LabelDetectionAggregateBy> {
        self.aggregate_by.as_ref()
    }
}
impl GetLabelDetectionRequestMetadata {
    /// Creates a new builder-style object to manufacture [`GetLabelDetectionRequestMetadata`](crate::types::GetLabelDetectionRequestMetadata).
    pub fn builder() -> crate::types::builders::GetLabelDetectionRequestMetadataBuilder {
        crate::types::builders::GetLabelDetectionRequestMetadataBuilder::default()
    }
}

/// A builder for [`GetLabelDetectionRequestMetadata`](crate::types::GetLabelDetectionRequestMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLabelDetectionRequestMetadataBuilder {
    pub(crate) sort_by: ::std::option::Option<crate::types::LabelDetectionSortBy>,
    pub(crate) aggregate_by: ::std::option::Option<crate::types::LabelDetectionAggregateBy>,
}
impl GetLabelDetectionRequestMetadataBuilder {
    /// <p>The sorting method chosen for a GetLabelDetection request.</p>
    pub fn sort_by(mut self, input: crate::types::LabelDetectionSortBy) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sorting method chosen for a GetLabelDetection request.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::LabelDetectionSortBy>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>The sorting method chosen for a GetLabelDetection request.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::LabelDetectionSortBy> {
        &self.sort_by
    }
    /// <p>The aggregation method chosen for a GetLabelDetection request.</p>
    pub fn aggregate_by(mut self, input: crate::types::LabelDetectionAggregateBy) -> Self {
        self.aggregate_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregation method chosen for a GetLabelDetection request.</p>
    pub fn set_aggregate_by(mut self, input: ::std::option::Option<crate::types::LabelDetectionAggregateBy>) -> Self {
        self.aggregate_by = input;
        self
    }
    /// <p>The aggregation method chosen for a GetLabelDetection request.</p>
    pub fn get_aggregate_by(&self) -> &::std::option::Option<crate::types::LabelDetectionAggregateBy> {
        &self.aggregate_by
    }
    /// Consumes the builder and constructs a [`GetLabelDetectionRequestMetadata`](crate::types::GetLabelDetectionRequestMetadata).
    pub fn build(self) -> crate::types::GetLabelDetectionRequestMetadata {
        crate::types::GetLabelDetectionRequestMetadata {
            sort_by: self.sort_by,
            aggregate_by: self.aggregate_by,
        }
    }
}
