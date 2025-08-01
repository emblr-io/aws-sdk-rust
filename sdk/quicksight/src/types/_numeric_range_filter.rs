// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A <code>NumericRangeFilter</code> filters values that are within the value range.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NumericRangeFilter {
    /// <p>An identifier that uniquely identifies a filter within a dashboard, analysis, or template.</p>
    pub filter_id: ::std::string::String,
    /// <p>The column that the filter is applied to.</p>
    pub column: ::std::option::Option<crate::types::ColumnIdentifier>,
    /// <p>Determines whether the minimum value in the filter value range should be included in the filtered results.</p>
    pub include_minimum: ::std::option::Option<bool>,
    /// <p>Determines whether the maximum value in the filter value range should be included in the filtered results.</p>
    pub include_maximum: ::std::option::Option<bool>,
    /// <p>The minimum value for the filter value range.</p>
    pub range_minimum: ::std::option::Option<crate::types::NumericRangeFilterValue>,
    /// <p>The maximum value for the filter value range.</p>
    pub range_maximum: ::std::option::Option<crate::types::NumericRangeFilterValue>,
    /// <p>Select all of the values. Null is not the assigned value of select all.</p>
    /// <ul>
    /// <li>
    /// <p><code>FILTER_ALL_VALUES</code></p></li>
    /// </ul>
    pub select_all_options: ::std::option::Option<crate::types::NumericFilterSelectAllOptions>,
    /// <p>The aggregation function of the filter.</p>
    pub aggregation_function: ::std::option::Option<crate::types::AggregationFunction>,
    /// <p>This option determines how null values should be treated when filtering data.</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL_VALUES</code>: Include null values in filtered results.</p></li>
    /// <li>
    /// <p><code>NULLS_ONLY</code>: Only include null values in filtered results.</p></li>
    /// <li>
    /// <p><code>NON_NULLS_ONLY</code>: Exclude null values from filtered results.</p></li>
    /// </ul>
    pub null_option: crate::types::FilterNullOption,
    /// <p>The default configurations for the associated controls. This applies only for filters that are scoped to multiple sheets.</p>
    pub default_filter_control_configuration: ::std::option::Option<crate::types::DefaultFilterControlConfiguration>,
}
impl NumericRangeFilter {
    /// <p>An identifier that uniquely identifies a filter within a dashboard, analysis, or template.</p>
    pub fn filter_id(&self) -> &str {
        use std::ops::Deref;
        self.filter_id.deref()
    }
    /// <p>The column that the filter is applied to.</p>
    pub fn column(&self) -> ::std::option::Option<&crate::types::ColumnIdentifier> {
        self.column.as_ref()
    }
    /// <p>Determines whether the minimum value in the filter value range should be included in the filtered results.</p>
    pub fn include_minimum(&self) -> ::std::option::Option<bool> {
        self.include_minimum
    }
    /// <p>Determines whether the maximum value in the filter value range should be included in the filtered results.</p>
    pub fn include_maximum(&self) -> ::std::option::Option<bool> {
        self.include_maximum
    }
    /// <p>The minimum value for the filter value range.</p>
    pub fn range_minimum(&self) -> ::std::option::Option<&crate::types::NumericRangeFilterValue> {
        self.range_minimum.as_ref()
    }
    /// <p>The maximum value for the filter value range.</p>
    pub fn range_maximum(&self) -> ::std::option::Option<&crate::types::NumericRangeFilterValue> {
        self.range_maximum.as_ref()
    }
    /// <p>Select all of the values. Null is not the assigned value of select all.</p>
    /// <ul>
    /// <li>
    /// <p><code>FILTER_ALL_VALUES</code></p></li>
    /// </ul>
    pub fn select_all_options(&self) -> ::std::option::Option<&crate::types::NumericFilterSelectAllOptions> {
        self.select_all_options.as_ref()
    }
    /// <p>The aggregation function of the filter.</p>
    pub fn aggregation_function(&self) -> ::std::option::Option<&crate::types::AggregationFunction> {
        self.aggregation_function.as_ref()
    }
    /// <p>This option determines how null values should be treated when filtering data.</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL_VALUES</code>: Include null values in filtered results.</p></li>
    /// <li>
    /// <p><code>NULLS_ONLY</code>: Only include null values in filtered results.</p></li>
    /// <li>
    /// <p><code>NON_NULLS_ONLY</code>: Exclude null values from filtered results.</p></li>
    /// </ul>
    pub fn null_option(&self) -> &crate::types::FilterNullOption {
        &self.null_option
    }
    /// <p>The default configurations for the associated controls. This applies only for filters that are scoped to multiple sheets.</p>
    pub fn default_filter_control_configuration(&self) -> ::std::option::Option<&crate::types::DefaultFilterControlConfiguration> {
        self.default_filter_control_configuration.as_ref()
    }
}
impl NumericRangeFilter {
    /// Creates a new builder-style object to manufacture [`NumericRangeFilter`](crate::types::NumericRangeFilter).
    pub fn builder() -> crate::types::builders::NumericRangeFilterBuilder {
        crate::types::builders::NumericRangeFilterBuilder::default()
    }
}

/// A builder for [`NumericRangeFilter`](crate::types::NumericRangeFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NumericRangeFilterBuilder {
    pub(crate) filter_id: ::std::option::Option<::std::string::String>,
    pub(crate) column: ::std::option::Option<crate::types::ColumnIdentifier>,
    pub(crate) include_minimum: ::std::option::Option<bool>,
    pub(crate) include_maximum: ::std::option::Option<bool>,
    pub(crate) range_minimum: ::std::option::Option<crate::types::NumericRangeFilterValue>,
    pub(crate) range_maximum: ::std::option::Option<crate::types::NumericRangeFilterValue>,
    pub(crate) select_all_options: ::std::option::Option<crate::types::NumericFilterSelectAllOptions>,
    pub(crate) aggregation_function: ::std::option::Option<crate::types::AggregationFunction>,
    pub(crate) null_option: ::std::option::Option<crate::types::FilterNullOption>,
    pub(crate) default_filter_control_configuration: ::std::option::Option<crate::types::DefaultFilterControlConfiguration>,
}
impl NumericRangeFilterBuilder {
    /// <p>An identifier that uniquely identifies a filter within a dashboard, analysis, or template.</p>
    /// This field is required.
    pub fn filter_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.filter_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier that uniquely identifies a filter within a dashboard, analysis, or template.</p>
    pub fn set_filter_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.filter_id = input;
        self
    }
    /// <p>An identifier that uniquely identifies a filter within a dashboard, analysis, or template.</p>
    pub fn get_filter_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.filter_id
    }
    /// <p>The column that the filter is applied to.</p>
    /// This field is required.
    pub fn column(mut self, input: crate::types::ColumnIdentifier) -> Self {
        self.column = ::std::option::Option::Some(input);
        self
    }
    /// <p>The column that the filter is applied to.</p>
    pub fn set_column(mut self, input: ::std::option::Option<crate::types::ColumnIdentifier>) -> Self {
        self.column = input;
        self
    }
    /// <p>The column that the filter is applied to.</p>
    pub fn get_column(&self) -> &::std::option::Option<crate::types::ColumnIdentifier> {
        &self.column
    }
    /// <p>Determines whether the minimum value in the filter value range should be included in the filtered results.</p>
    pub fn include_minimum(mut self, input: bool) -> Self {
        self.include_minimum = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines whether the minimum value in the filter value range should be included in the filtered results.</p>
    pub fn set_include_minimum(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_minimum = input;
        self
    }
    /// <p>Determines whether the minimum value in the filter value range should be included in the filtered results.</p>
    pub fn get_include_minimum(&self) -> &::std::option::Option<bool> {
        &self.include_minimum
    }
    /// <p>Determines whether the maximum value in the filter value range should be included in the filtered results.</p>
    pub fn include_maximum(mut self, input: bool) -> Self {
        self.include_maximum = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines whether the maximum value in the filter value range should be included in the filtered results.</p>
    pub fn set_include_maximum(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_maximum = input;
        self
    }
    /// <p>Determines whether the maximum value in the filter value range should be included in the filtered results.</p>
    pub fn get_include_maximum(&self) -> &::std::option::Option<bool> {
        &self.include_maximum
    }
    /// <p>The minimum value for the filter value range.</p>
    pub fn range_minimum(mut self, input: crate::types::NumericRangeFilterValue) -> Self {
        self.range_minimum = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum value for the filter value range.</p>
    pub fn set_range_minimum(mut self, input: ::std::option::Option<crate::types::NumericRangeFilterValue>) -> Self {
        self.range_minimum = input;
        self
    }
    /// <p>The minimum value for the filter value range.</p>
    pub fn get_range_minimum(&self) -> &::std::option::Option<crate::types::NumericRangeFilterValue> {
        &self.range_minimum
    }
    /// <p>The maximum value for the filter value range.</p>
    pub fn range_maximum(mut self, input: crate::types::NumericRangeFilterValue) -> Self {
        self.range_maximum = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum value for the filter value range.</p>
    pub fn set_range_maximum(mut self, input: ::std::option::Option<crate::types::NumericRangeFilterValue>) -> Self {
        self.range_maximum = input;
        self
    }
    /// <p>The maximum value for the filter value range.</p>
    pub fn get_range_maximum(&self) -> &::std::option::Option<crate::types::NumericRangeFilterValue> {
        &self.range_maximum
    }
    /// <p>Select all of the values. Null is not the assigned value of select all.</p>
    /// <ul>
    /// <li>
    /// <p><code>FILTER_ALL_VALUES</code></p></li>
    /// </ul>
    pub fn select_all_options(mut self, input: crate::types::NumericFilterSelectAllOptions) -> Self {
        self.select_all_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Select all of the values. Null is not the assigned value of select all.</p>
    /// <ul>
    /// <li>
    /// <p><code>FILTER_ALL_VALUES</code></p></li>
    /// </ul>
    pub fn set_select_all_options(mut self, input: ::std::option::Option<crate::types::NumericFilterSelectAllOptions>) -> Self {
        self.select_all_options = input;
        self
    }
    /// <p>Select all of the values. Null is not the assigned value of select all.</p>
    /// <ul>
    /// <li>
    /// <p><code>FILTER_ALL_VALUES</code></p></li>
    /// </ul>
    pub fn get_select_all_options(&self) -> &::std::option::Option<crate::types::NumericFilterSelectAllOptions> {
        &self.select_all_options
    }
    /// <p>The aggregation function of the filter.</p>
    pub fn aggregation_function(mut self, input: crate::types::AggregationFunction) -> Self {
        self.aggregation_function = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregation function of the filter.</p>
    pub fn set_aggregation_function(mut self, input: ::std::option::Option<crate::types::AggregationFunction>) -> Self {
        self.aggregation_function = input;
        self
    }
    /// <p>The aggregation function of the filter.</p>
    pub fn get_aggregation_function(&self) -> &::std::option::Option<crate::types::AggregationFunction> {
        &self.aggregation_function
    }
    /// <p>This option determines how null values should be treated when filtering data.</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL_VALUES</code>: Include null values in filtered results.</p></li>
    /// <li>
    /// <p><code>NULLS_ONLY</code>: Only include null values in filtered results.</p></li>
    /// <li>
    /// <p><code>NON_NULLS_ONLY</code>: Exclude null values from filtered results.</p></li>
    /// </ul>
    /// This field is required.
    pub fn null_option(mut self, input: crate::types::FilterNullOption) -> Self {
        self.null_option = ::std::option::Option::Some(input);
        self
    }
    /// <p>This option determines how null values should be treated when filtering data.</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL_VALUES</code>: Include null values in filtered results.</p></li>
    /// <li>
    /// <p><code>NULLS_ONLY</code>: Only include null values in filtered results.</p></li>
    /// <li>
    /// <p><code>NON_NULLS_ONLY</code>: Exclude null values from filtered results.</p></li>
    /// </ul>
    pub fn set_null_option(mut self, input: ::std::option::Option<crate::types::FilterNullOption>) -> Self {
        self.null_option = input;
        self
    }
    /// <p>This option determines how null values should be treated when filtering data.</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL_VALUES</code>: Include null values in filtered results.</p></li>
    /// <li>
    /// <p><code>NULLS_ONLY</code>: Only include null values in filtered results.</p></li>
    /// <li>
    /// <p><code>NON_NULLS_ONLY</code>: Exclude null values from filtered results.</p></li>
    /// </ul>
    pub fn get_null_option(&self) -> &::std::option::Option<crate::types::FilterNullOption> {
        &self.null_option
    }
    /// <p>The default configurations for the associated controls. This applies only for filters that are scoped to multiple sheets.</p>
    pub fn default_filter_control_configuration(mut self, input: crate::types::DefaultFilterControlConfiguration) -> Self {
        self.default_filter_control_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The default configurations for the associated controls. This applies only for filters that are scoped to multiple sheets.</p>
    pub fn set_default_filter_control_configuration(mut self, input: ::std::option::Option<crate::types::DefaultFilterControlConfiguration>) -> Self {
        self.default_filter_control_configuration = input;
        self
    }
    /// <p>The default configurations for the associated controls. This applies only for filters that are scoped to multiple sheets.</p>
    pub fn get_default_filter_control_configuration(&self) -> &::std::option::Option<crate::types::DefaultFilterControlConfiguration> {
        &self.default_filter_control_configuration
    }
    /// Consumes the builder and constructs a [`NumericRangeFilter`](crate::types::NumericRangeFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`filter_id`](crate::types::builders::NumericRangeFilterBuilder::filter_id)
    /// - [`null_option`](crate::types::builders::NumericRangeFilterBuilder::null_option)
    pub fn build(self) -> ::std::result::Result<crate::types::NumericRangeFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::NumericRangeFilter {
            filter_id: self.filter_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "filter_id",
                    "filter_id was not specified but it is required when building NumericRangeFilter",
                )
            })?,
            column: self.column,
            include_minimum: self.include_minimum,
            include_maximum: self.include_maximum,
            range_minimum: self.range_minimum,
            range_maximum: self.range_maximum,
            select_all_options: self.select_all_options,
            aggregation_function: self.aggregation_function,
            null_option: self.null_option.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "null_option",
                    "null_option was not specified but it is required when building NumericRangeFilter",
                )
            })?,
            default_filter_control_configuration: self.default_filter_control_configuration,
        })
    }
}
