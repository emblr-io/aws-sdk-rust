// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details that define an aggregation based on finding type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FindingTypeAggregation {
    /// <p>The finding type to aggregate.</p>
    pub finding_type: ::std::option::Option<crate::types::AggregationFindingType>,
    /// <p>The resource type to aggregate.</p>
    pub resource_type: ::std::option::Option<crate::types::AggregationResourceType>,
    /// <p>The order to sort results by.</p>
    pub sort_order: ::std::option::Option<crate::types::SortOrder>,
    /// <p>The value to sort results by.</p>
    pub sort_by: ::std::option::Option<crate::types::FindingTypeSortBy>,
}
impl FindingTypeAggregation {
    /// <p>The finding type to aggregate.</p>
    pub fn finding_type(&self) -> ::std::option::Option<&crate::types::AggregationFindingType> {
        self.finding_type.as_ref()
    }
    /// <p>The resource type to aggregate.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::AggregationResourceType> {
        self.resource_type.as_ref()
    }
    /// <p>The order to sort results by.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrder> {
        self.sort_order.as_ref()
    }
    /// <p>The value to sort results by.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::FindingTypeSortBy> {
        self.sort_by.as_ref()
    }
}
impl FindingTypeAggregation {
    /// Creates a new builder-style object to manufacture [`FindingTypeAggregation`](crate::types::FindingTypeAggregation).
    pub fn builder() -> crate::types::builders::FindingTypeAggregationBuilder {
        crate::types::builders::FindingTypeAggregationBuilder::default()
    }
}

/// A builder for [`FindingTypeAggregation`](crate::types::FindingTypeAggregation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FindingTypeAggregationBuilder {
    pub(crate) finding_type: ::std::option::Option<crate::types::AggregationFindingType>,
    pub(crate) resource_type: ::std::option::Option<crate::types::AggregationResourceType>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrder>,
    pub(crate) sort_by: ::std::option::Option<crate::types::FindingTypeSortBy>,
}
impl FindingTypeAggregationBuilder {
    /// <p>The finding type to aggregate.</p>
    pub fn finding_type(mut self, input: crate::types::AggregationFindingType) -> Self {
        self.finding_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The finding type to aggregate.</p>
    pub fn set_finding_type(mut self, input: ::std::option::Option<crate::types::AggregationFindingType>) -> Self {
        self.finding_type = input;
        self
    }
    /// <p>The finding type to aggregate.</p>
    pub fn get_finding_type(&self) -> &::std::option::Option<crate::types::AggregationFindingType> {
        &self.finding_type
    }
    /// <p>The resource type to aggregate.</p>
    pub fn resource_type(mut self, input: crate::types::AggregationResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resource type to aggregate.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::AggregationResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The resource type to aggregate.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::AggregationResourceType> {
        &self.resource_type
    }
    /// <p>The order to sort results by.</p>
    pub fn sort_order(mut self, input: crate::types::SortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The order to sort results by.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>The order to sort results by.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort_order
    }
    /// <p>The value to sort results by.</p>
    pub fn sort_by(mut self, input: crate::types::FindingTypeSortBy) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value to sort results by.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::FindingTypeSortBy>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>The value to sort results by.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::FindingTypeSortBy> {
        &self.sort_by
    }
    /// Consumes the builder and constructs a [`FindingTypeAggregation`](crate::types::FindingTypeAggregation).
    pub fn build(self) -> crate::types::FindingTypeAggregation {
        crate::types::FindingTypeAggregation {
            finding_type: self.finding_type,
            resource_type: self.resource_type,
            sort_order: self.sort_order,
            sort_by: self.sort_by,
        }
    }
}
