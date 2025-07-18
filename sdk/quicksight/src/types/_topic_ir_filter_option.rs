// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The definition for a <code>TopicIRFilterOption</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TopicIrFilterOption {
    /// <p>The filter type for the <code>TopicIRFilterOption</code>.</p>
    pub filter_type: ::std::option::Option<crate::types::TopicIrFilterType>,
    /// <p>The filter class for the <code>TopicIRFilterOption</code>.</p>
    pub filter_class: ::std::option::Option<crate::types::FilterClass>,
    /// <p>The operand field for the <code>TopicIRFilterOption</code>.</p>
    pub operand_field: ::std::option::Option<crate::types::Identifier>,
    /// <p>The function for the <code>TopicIRFilterOption</code>.</p>
    pub function: ::std::option::Option<crate::types::TopicIrFilterFunction>,
    /// <p>The constant for the <code>TopicIRFilterOption</code>.</p>
    pub constant: ::std::option::Option<crate::types::TopicConstantValue>,
    /// <p>The inverse for the <code>TopicIRFilterOption</code>.</p>
    pub inverse: bool,
    /// <p>The null filter for the <code>TopicIRFilterOption</code>.</p>
    pub null_filter: ::std::option::Option<crate::types::NullFilterOption>,
    /// <p>The aggregation for the <code>TopicIRFilterOption</code>.</p>
    pub aggregation: ::std::option::Option<crate::types::AggType>,
    /// <p>The aggregation function parameters for the <code>TopicIRFilterOption</code>.</p>
    pub aggregation_function_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.</p>
    pub aggregation_partition_by: ::std::option::Option<::std::vec::Vec<crate::types::AggregationPartitionBy>>,
    /// <p>The range for the <code>TopicIRFilterOption</code>.</p>
    pub range: ::std::option::Option<crate::types::TopicConstantValue>,
    /// <p>The inclusive for the <code>TopicIRFilterOption</code>.</p>
    pub inclusive: bool,
    /// <p>The time granularity for the <code>TopicIRFilterOption</code>.</p>
    pub time_granularity: ::std::option::Option<crate::types::TimeGranularity>,
    /// <p>The last next offset for the <code>TopicIRFilterOption</code>.</p>
    pub last_next_offset: ::std::option::Option<crate::types::TopicConstantValue>,
    /// <p>The agg metrics for the <code>TopicIRFilterOption</code>.</p>
    pub agg_metrics: ::std::option::Option<::std::vec::Vec<crate::types::FilterAggMetrics>>,
    /// <p>The <code>TopBottomLimit</code> for the <code>TopicIRFilterOption</code>.</p>
    pub top_bottom_limit: ::std::option::Option<crate::types::TopicConstantValue>,
    /// <p>The sort direction for the <code>TopicIRFilterOption</code>.</p>
    pub sort_direction: ::std::option::Option<crate::types::TopicSortDirection>,
    /// <p>The anchor for the <code>TopicIRFilterOption</code>.</p>
    pub anchor: ::std::option::Option<crate::types::Anchor>,
}
impl TopicIrFilterOption {
    /// <p>The filter type for the <code>TopicIRFilterOption</code>.</p>
    pub fn filter_type(&self) -> ::std::option::Option<&crate::types::TopicIrFilterType> {
        self.filter_type.as_ref()
    }
    /// <p>The filter class for the <code>TopicIRFilterOption</code>.</p>
    pub fn filter_class(&self) -> ::std::option::Option<&crate::types::FilterClass> {
        self.filter_class.as_ref()
    }
    /// <p>The operand field for the <code>TopicIRFilterOption</code>.</p>
    pub fn operand_field(&self) -> ::std::option::Option<&crate::types::Identifier> {
        self.operand_field.as_ref()
    }
    /// <p>The function for the <code>TopicIRFilterOption</code>.</p>
    pub fn function(&self) -> ::std::option::Option<&crate::types::TopicIrFilterFunction> {
        self.function.as_ref()
    }
    /// <p>The constant for the <code>TopicIRFilterOption</code>.</p>
    pub fn constant(&self) -> ::std::option::Option<&crate::types::TopicConstantValue> {
        self.constant.as_ref()
    }
    /// <p>The inverse for the <code>TopicIRFilterOption</code>.</p>
    pub fn inverse(&self) -> bool {
        self.inverse
    }
    /// <p>The null filter for the <code>TopicIRFilterOption</code>.</p>
    pub fn null_filter(&self) -> ::std::option::Option<&crate::types::NullFilterOption> {
        self.null_filter.as_ref()
    }
    /// <p>The aggregation for the <code>TopicIRFilterOption</code>.</p>
    pub fn aggregation(&self) -> ::std::option::Option<&crate::types::AggType> {
        self.aggregation.as_ref()
    }
    /// <p>The aggregation function parameters for the <code>TopicIRFilterOption</code>.</p>
    pub fn aggregation_function_parameters(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.aggregation_function_parameters.as_ref()
    }
    /// <p>The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.aggregation_partition_by.is_none()`.
    pub fn aggregation_partition_by(&self) -> &[crate::types::AggregationPartitionBy] {
        self.aggregation_partition_by.as_deref().unwrap_or_default()
    }
    /// <p>The range for the <code>TopicIRFilterOption</code>.</p>
    pub fn range(&self) -> ::std::option::Option<&crate::types::TopicConstantValue> {
        self.range.as_ref()
    }
    /// <p>The inclusive for the <code>TopicIRFilterOption</code>.</p>
    pub fn inclusive(&self) -> bool {
        self.inclusive
    }
    /// <p>The time granularity for the <code>TopicIRFilterOption</code>.</p>
    pub fn time_granularity(&self) -> ::std::option::Option<&crate::types::TimeGranularity> {
        self.time_granularity.as_ref()
    }
    /// <p>The last next offset for the <code>TopicIRFilterOption</code>.</p>
    pub fn last_next_offset(&self) -> ::std::option::Option<&crate::types::TopicConstantValue> {
        self.last_next_offset.as_ref()
    }
    /// <p>The agg metrics for the <code>TopicIRFilterOption</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.agg_metrics.is_none()`.
    pub fn agg_metrics(&self) -> &[crate::types::FilterAggMetrics] {
        self.agg_metrics.as_deref().unwrap_or_default()
    }
    /// <p>The <code>TopBottomLimit</code> for the <code>TopicIRFilterOption</code>.</p>
    pub fn top_bottom_limit(&self) -> ::std::option::Option<&crate::types::TopicConstantValue> {
        self.top_bottom_limit.as_ref()
    }
    /// <p>The sort direction for the <code>TopicIRFilterOption</code>.</p>
    pub fn sort_direction(&self) -> ::std::option::Option<&crate::types::TopicSortDirection> {
        self.sort_direction.as_ref()
    }
    /// <p>The anchor for the <code>TopicIRFilterOption</code>.</p>
    pub fn anchor(&self) -> ::std::option::Option<&crate::types::Anchor> {
        self.anchor.as_ref()
    }
}
impl TopicIrFilterOption {
    /// Creates a new builder-style object to manufacture [`TopicIrFilterOption`](crate::types::TopicIrFilterOption).
    pub fn builder() -> crate::types::builders::TopicIrFilterOptionBuilder {
        crate::types::builders::TopicIrFilterOptionBuilder::default()
    }
}

/// A builder for [`TopicIrFilterOption`](crate::types::TopicIrFilterOption).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TopicIrFilterOptionBuilder {
    pub(crate) filter_type: ::std::option::Option<crate::types::TopicIrFilterType>,
    pub(crate) filter_class: ::std::option::Option<crate::types::FilterClass>,
    pub(crate) operand_field: ::std::option::Option<crate::types::Identifier>,
    pub(crate) function: ::std::option::Option<crate::types::TopicIrFilterFunction>,
    pub(crate) constant: ::std::option::Option<crate::types::TopicConstantValue>,
    pub(crate) inverse: ::std::option::Option<bool>,
    pub(crate) null_filter: ::std::option::Option<crate::types::NullFilterOption>,
    pub(crate) aggregation: ::std::option::Option<crate::types::AggType>,
    pub(crate) aggregation_function_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) aggregation_partition_by: ::std::option::Option<::std::vec::Vec<crate::types::AggregationPartitionBy>>,
    pub(crate) range: ::std::option::Option<crate::types::TopicConstantValue>,
    pub(crate) inclusive: ::std::option::Option<bool>,
    pub(crate) time_granularity: ::std::option::Option<crate::types::TimeGranularity>,
    pub(crate) last_next_offset: ::std::option::Option<crate::types::TopicConstantValue>,
    pub(crate) agg_metrics: ::std::option::Option<::std::vec::Vec<crate::types::FilterAggMetrics>>,
    pub(crate) top_bottom_limit: ::std::option::Option<crate::types::TopicConstantValue>,
    pub(crate) sort_direction: ::std::option::Option<crate::types::TopicSortDirection>,
    pub(crate) anchor: ::std::option::Option<crate::types::Anchor>,
}
impl TopicIrFilterOptionBuilder {
    /// <p>The filter type for the <code>TopicIRFilterOption</code>.</p>
    pub fn filter_type(mut self, input: crate::types::TopicIrFilterType) -> Self {
        self.filter_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The filter type for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_filter_type(mut self, input: ::std::option::Option<crate::types::TopicIrFilterType>) -> Self {
        self.filter_type = input;
        self
    }
    /// <p>The filter type for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_filter_type(&self) -> &::std::option::Option<crate::types::TopicIrFilterType> {
        &self.filter_type
    }
    /// <p>The filter class for the <code>TopicIRFilterOption</code>.</p>
    pub fn filter_class(mut self, input: crate::types::FilterClass) -> Self {
        self.filter_class = ::std::option::Option::Some(input);
        self
    }
    /// <p>The filter class for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_filter_class(mut self, input: ::std::option::Option<crate::types::FilterClass>) -> Self {
        self.filter_class = input;
        self
    }
    /// <p>The filter class for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_filter_class(&self) -> &::std::option::Option<crate::types::FilterClass> {
        &self.filter_class
    }
    /// <p>The operand field for the <code>TopicIRFilterOption</code>.</p>
    pub fn operand_field(mut self, input: crate::types::Identifier) -> Self {
        self.operand_field = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operand field for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_operand_field(mut self, input: ::std::option::Option<crate::types::Identifier>) -> Self {
        self.operand_field = input;
        self
    }
    /// <p>The operand field for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_operand_field(&self) -> &::std::option::Option<crate::types::Identifier> {
        &self.operand_field
    }
    /// <p>The function for the <code>TopicIRFilterOption</code>.</p>
    pub fn function(mut self, input: crate::types::TopicIrFilterFunction) -> Self {
        self.function = ::std::option::Option::Some(input);
        self
    }
    /// <p>The function for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_function(mut self, input: ::std::option::Option<crate::types::TopicIrFilterFunction>) -> Self {
        self.function = input;
        self
    }
    /// <p>The function for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_function(&self) -> &::std::option::Option<crate::types::TopicIrFilterFunction> {
        &self.function
    }
    /// <p>The constant for the <code>TopicIRFilterOption</code>.</p>
    pub fn constant(mut self, input: crate::types::TopicConstantValue) -> Self {
        self.constant = ::std::option::Option::Some(input);
        self
    }
    /// <p>The constant for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_constant(mut self, input: ::std::option::Option<crate::types::TopicConstantValue>) -> Self {
        self.constant = input;
        self
    }
    /// <p>The constant for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_constant(&self) -> &::std::option::Option<crate::types::TopicConstantValue> {
        &self.constant
    }
    /// <p>The inverse for the <code>TopicIRFilterOption</code>.</p>
    pub fn inverse(mut self, input: bool) -> Self {
        self.inverse = ::std::option::Option::Some(input);
        self
    }
    /// <p>The inverse for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_inverse(mut self, input: ::std::option::Option<bool>) -> Self {
        self.inverse = input;
        self
    }
    /// <p>The inverse for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_inverse(&self) -> &::std::option::Option<bool> {
        &self.inverse
    }
    /// <p>The null filter for the <code>TopicIRFilterOption</code>.</p>
    pub fn null_filter(mut self, input: crate::types::NullFilterOption) -> Self {
        self.null_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>The null filter for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_null_filter(mut self, input: ::std::option::Option<crate::types::NullFilterOption>) -> Self {
        self.null_filter = input;
        self
    }
    /// <p>The null filter for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_null_filter(&self) -> &::std::option::Option<crate::types::NullFilterOption> {
        &self.null_filter
    }
    /// <p>The aggregation for the <code>TopicIRFilterOption</code>.</p>
    pub fn aggregation(mut self, input: crate::types::AggType) -> Self {
        self.aggregation = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregation for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_aggregation(mut self, input: ::std::option::Option<crate::types::AggType>) -> Self {
        self.aggregation = input;
        self
    }
    /// <p>The aggregation for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_aggregation(&self) -> &::std::option::Option<crate::types::AggType> {
        &self.aggregation
    }
    /// Adds a key-value pair to `aggregation_function_parameters`.
    ///
    /// To override the contents of this collection use [`set_aggregation_function_parameters`](Self::set_aggregation_function_parameters).
    ///
    /// <p>The aggregation function parameters for the <code>TopicIRFilterOption</code>.</p>
    pub fn aggregation_function_parameters(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.aggregation_function_parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.aggregation_function_parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The aggregation function parameters for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_aggregation_function_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.aggregation_function_parameters = input;
        self
    }
    /// <p>The aggregation function parameters for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_aggregation_function_parameters(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.aggregation_function_parameters
    }
    /// Appends an item to `aggregation_partition_by`.
    ///
    /// To override the contents of this collection use [`set_aggregation_partition_by`](Self::set_aggregation_partition_by).
    ///
    /// <p>The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.</p>
    pub fn aggregation_partition_by(mut self, input: crate::types::AggregationPartitionBy) -> Self {
        let mut v = self.aggregation_partition_by.unwrap_or_default();
        v.push(input);
        self.aggregation_partition_by = ::std::option::Option::Some(v);
        self
    }
    /// <p>The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_aggregation_partition_by(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AggregationPartitionBy>>) -> Self {
        self.aggregation_partition_by = input;
        self
    }
    /// <p>The <code>AggregationPartitionBy</code> for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_aggregation_partition_by(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AggregationPartitionBy>> {
        &self.aggregation_partition_by
    }
    /// <p>The range for the <code>TopicIRFilterOption</code>.</p>
    pub fn range(mut self, input: crate::types::TopicConstantValue) -> Self {
        self.range = ::std::option::Option::Some(input);
        self
    }
    /// <p>The range for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_range(mut self, input: ::std::option::Option<crate::types::TopicConstantValue>) -> Self {
        self.range = input;
        self
    }
    /// <p>The range for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_range(&self) -> &::std::option::Option<crate::types::TopicConstantValue> {
        &self.range
    }
    /// <p>The inclusive for the <code>TopicIRFilterOption</code>.</p>
    pub fn inclusive(mut self, input: bool) -> Self {
        self.inclusive = ::std::option::Option::Some(input);
        self
    }
    /// <p>The inclusive for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_inclusive(mut self, input: ::std::option::Option<bool>) -> Self {
        self.inclusive = input;
        self
    }
    /// <p>The inclusive for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_inclusive(&self) -> &::std::option::Option<bool> {
        &self.inclusive
    }
    /// <p>The time granularity for the <code>TopicIRFilterOption</code>.</p>
    pub fn time_granularity(mut self, input: crate::types::TimeGranularity) -> Self {
        self.time_granularity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time granularity for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_time_granularity(mut self, input: ::std::option::Option<crate::types::TimeGranularity>) -> Self {
        self.time_granularity = input;
        self
    }
    /// <p>The time granularity for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_time_granularity(&self) -> &::std::option::Option<crate::types::TimeGranularity> {
        &self.time_granularity
    }
    /// <p>The last next offset for the <code>TopicIRFilterOption</code>.</p>
    pub fn last_next_offset(mut self, input: crate::types::TopicConstantValue) -> Self {
        self.last_next_offset = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last next offset for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_last_next_offset(mut self, input: ::std::option::Option<crate::types::TopicConstantValue>) -> Self {
        self.last_next_offset = input;
        self
    }
    /// <p>The last next offset for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_last_next_offset(&self) -> &::std::option::Option<crate::types::TopicConstantValue> {
        &self.last_next_offset
    }
    /// Appends an item to `agg_metrics`.
    ///
    /// To override the contents of this collection use [`set_agg_metrics`](Self::set_agg_metrics).
    ///
    /// <p>The agg metrics for the <code>TopicIRFilterOption</code>.</p>
    pub fn agg_metrics(mut self, input: crate::types::FilterAggMetrics) -> Self {
        let mut v = self.agg_metrics.unwrap_or_default();
        v.push(input);
        self.agg_metrics = ::std::option::Option::Some(v);
        self
    }
    /// <p>The agg metrics for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_agg_metrics(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FilterAggMetrics>>) -> Self {
        self.agg_metrics = input;
        self
    }
    /// <p>The agg metrics for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_agg_metrics(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FilterAggMetrics>> {
        &self.agg_metrics
    }
    /// <p>The <code>TopBottomLimit</code> for the <code>TopicIRFilterOption</code>.</p>
    pub fn top_bottom_limit(mut self, input: crate::types::TopicConstantValue) -> Self {
        self.top_bottom_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>TopBottomLimit</code> for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_top_bottom_limit(mut self, input: ::std::option::Option<crate::types::TopicConstantValue>) -> Self {
        self.top_bottom_limit = input;
        self
    }
    /// <p>The <code>TopBottomLimit</code> for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_top_bottom_limit(&self) -> &::std::option::Option<crate::types::TopicConstantValue> {
        &self.top_bottom_limit
    }
    /// <p>The sort direction for the <code>TopicIRFilterOption</code>.</p>
    pub fn sort_direction(mut self, input: crate::types::TopicSortDirection) -> Self {
        self.sort_direction = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sort direction for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_sort_direction(mut self, input: ::std::option::Option<crate::types::TopicSortDirection>) -> Self {
        self.sort_direction = input;
        self
    }
    /// <p>The sort direction for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_sort_direction(&self) -> &::std::option::Option<crate::types::TopicSortDirection> {
        &self.sort_direction
    }
    /// <p>The anchor for the <code>TopicIRFilterOption</code>.</p>
    pub fn anchor(mut self, input: crate::types::Anchor) -> Self {
        self.anchor = ::std::option::Option::Some(input);
        self
    }
    /// <p>The anchor for the <code>TopicIRFilterOption</code>.</p>
    pub fn set_anchor(mut self, input: ::std::option::Option<crate::types::Anchor>) -> Self {
        self.anchor = input;
        self
    }
    /// <p>The anchor for the <code>TopicIRFilterOption</code>.</p>
    pub fn get_anchor(&self) -> &::std::option::Option<crate::types::Anchor> {
        &self.anchor
    }
    /// Consumes the builder and constructs a [`TopicIrFilterOption`](crate::types::TopicIrFilterOption).
    pub fn build(self) -> crate::types::TopicIrFilterOption {
        crate::types::TopicIrFilterOption {
            filter_type: self.filter_type,
            filter_class: self.filter_class,
            operand_field: self.operand_field,
            function: self.function,
            constant: self.constant,
            inverse: self.inverse.unwrap_or_default(),
            null_filter: self.null_filter,
            aggregation: self.aggregation,
            aggregation_function_parameters: self.aggregation_function_parameters,
            aggregation_partition_by: self.aggregation_partition_by,
            range: self.range,
            inclusive: self.inclusive.unwrap_or_default(),
            time_granularity: self.time_granularity,
            last_next_offset: self.last_next_offset,
            agg_metrics: self.agg_metrics,
            top_bottom_limit: self.top_bottom_limit,
            sort_direction: self.sort_direction,
            anchor: self.anchor,
        }
    }
}
