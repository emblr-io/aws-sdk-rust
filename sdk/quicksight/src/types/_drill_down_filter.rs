// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The drill down filter for the column hierarchies.</p>
/// <p>This is a union type structure. For this structure to be valid, only one of the attributes can be defined.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DrillDownFilter {
    /// <p>The numeric equality type drill down filter. This filter is used for number type columns.</p>
    pub numeric_equality_filter: ::std::option::Option<crate::types::NumericEqualityDrillDownFilter>,
    /// <p>The category type drill down filter. This filter is used for string type columns.</p>
    pub category_filter: ::std::option::Option<crate::types::CategoryDrillDownFilter>,
    /// <p>The time range drill down filter. This filter is used for date time columns.</p>
    pub time_range_filter: ::std::option::Option<crate::types::TimeRangeDrillDownFilter>,
}
impl DrillDownFilter {
    /// <p>The numeric equality type drill down filter. This filter is used for number type columns.</p>
    pub fn numeric_equality_filter(&self) -> ::std::option::Option<&crate::types::NumericEqualityDrillDownFilter> {
        self.numeric_equality_filter.as_ref()
    }
    /// <p>The category type drill down filter. This filter is used for string type columns.</p>
    pub fn category_filter(&self) -> ::std::option::Option<&crate::types::CategoryDrillDownFilter> {
        self.category_filter.as_ref()
    }
    /// <p>The time range drill down filter. This filter is used for date time columns.</p>
    pub fn time_range_filter(&self) -> ::std::option::Option<&crate::types::TimeRangeDrillDownFilter> {
        self.time_range_filter.as_ref()
    }
}
impl DrillDownFilter {
    /// Creates a new builder-style object to manufacture [`DrillDownFilter`](crate::types::DrillDownFilter).
    pub fn builder() -> crate::types::builders::DrillDownFilterBuilder {
        crate::types::builders::DrillDownFilterBuilder::default()
    }
}

/// A builder for [`DrillDownFilter`](crate::types::DrillDownFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DrillDownFilterBuilder {
    pub(crate) numeric_equality_filter: ::std::option::Option<crate::types::NumericEqualityDrillDownFilter>,
    pub(crate) category_filter: ::std::option::Option<crate::types::CategoryDrillDownFilter>,
    pub(crate) time_range_filter: ::std::option::Option<crate::types::TimeRangeDrillDownFilter>,
}
impl DrillDownFilterBuilder {
    /// <p>The numeric equality type drill down filter. This filter is used for number type columns.</p>
    pub fn numeric_equality_filter(mut self, input: crate::types::NumericEqualityDrillDownFilter) -> Self {
        self.numeric_equality_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>The numeric equality type drill down filter. This filter is used for number type columns.</p>
    pub fn set_numeric_equality_filter(mut self, input: ::std::option::Option<crate::types::NumericEqualityDrillDownFilter>) -> Self {
        self.numeric_equality_filter = input;
        self
    }
    /// <p>The numeric equality type drill down filter. This filter is used for number type columns.</p>
    pub fn get_numeric_equality_filter(&self) -> &::std::option::Option<crate::types::NumericEqualityDrillDownFilter> {
        &self.numeric_equality_filter
    }
    /// <p>The category type drill down filter. This filter is used for string type columns.</p>
    pub fn category_filter(mut self, input: crate::types::CategoryDrillDownFilter) -> Self {
        self.category_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>The category type drill down filter. This filter is used for string type columns.</p>
    pub fn set_category_filter(mut self, input: ::std::option::Option<crate::types::CategoryDrillDownFilter>) -> Self {
        self.category_filter = input;
        self
    }
    /// <p>The category type drill down filter. This filter is used for string type columns.</p>
    pub fn get_category_filter(&self) -> &::std::option::Option<crate::types::CategoryDrillDownFilter> {
        &self.category_filter
    }
    /// <p>The time range drill down filter. This filter is used for date time columns.</p>
    pub fn time_range_filter(mut self, input: crate::types::TimeRangeDrillDownFilter) -> Self {
        self.time_range_filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time range drill down filter. This filter is used for date time columns.</p>
    pub fn set_time_range_filter(mut self, input: ::std::option::Option<crate::types::TimeRangeDrillDownFilter>) -> Self {
        self.time_range_filter = input;
        self
    }
    /// <p>The time range drill down filter. This filter is used for date time columns.</p>
    pub fn get_time_range_filter(&self) -> &::std::option::Option<crate::types::TimeRangeDrillDownFilter> {
        &self.time_range_filter
    }
    /// Consumes the builder and constructs a [`DrillDownFilter`](crate::types::DrillDownFilter).
    pub fn build(self) -> crate::types::DrillDownFilter {
        crate::types::DrillDownFilter {
            numeric_equality_filter: self.numeric_equality_filter,
            category_filter: self.category_filter,
            time_range_filter: self.time_range_filter,
        }
    }
}
