// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines column statistics supported for fixed-point number data columns.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DecimalColumnStatisticsData {
    /// <p>The lowest value in the column.</p>
    pub minimum_value: ::std::option::Option<crate::types::DecimalNumber>,
    /// <p>The highest value in the column.</p>
    pub maximum_value: ::std::option::Option<crate::types::DecimalNumber>,
    /// <p>The number of null values in the column.</p>
    pub number_of_nulls: i64,
    /// <p>The number of distinct values in a column.</p>
    pub number_of_distinct_values: i64,
}
impl DecimalColumnStatisticsData {
    /// <p>The lowest value in the column.</p>
    pub fn minimum_value(&self) -> ::std::option::Option<&crate::types::DecimalNumber> {
        self.minimum_value.as_ref()
    }
    /// <p>The highest value in the column.</p>
    pub fn maximum_value(&self) -> ::std::option::Option<&crate::types::DecimalNumber> {
        self.maximum_value.as_ref()
    }
    /// <p>The number of null values in the column.</p>
    pub fn number_of_nulls(&self) -> i64 {
        self.number_of_nulls
    }
    /// <p>The number of distinct values in a column.</p>
    pub fn number_of_distinct_values(&self) -> i64 {
        self.number_of_distinct_values
    }
}
impl DecimalColumnStatisticsData {
    /// Creates a new builder-style object to manufacture [`DecimalColumnStatisticsData`](crate::types::DecimalColumnStatisticsData).
    pub fn builder() -> crate::types::builders::DecimalColumnStatisticsDataBuilder {
        crate::types::builders::DecimalColumnStatisticsDataBuilder::default()
    }
}

/// A builder for [`DecimalColumnStatisticsData`](crate::types::DecimalColumnStatisticsData).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DecimalColumnStatisticsDataBuilder {
    pub(crate) minimum_value: ::std::option::Option<crate::types::DecimalNumber>,
    pub(crate) maximum_value: ::std::option::Option<crate::types::DecimalNumber>,
    pub(crate) number_of_nulls: ::std::option::Option<i64>,
    pub(crate) number_of_distinct_values: ::std::option::Option<i64>,
}
impl DecimalColumnStatisticsDataBuilder {
    /// <p>The lowest value in the column.</p>
    pub fn minimum_value(mut self, input: crate::types::DecimalNumber) -> Self {
        self.minimum_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The lowest value in the column.</p>
    pub fn set_minimum_value(mut self, input: ::std::option::Option<crate::types::DecimalNumber>) -> Self {
        self.minimum_value = input;
        self
    }
    /// <p>The lowest value in the column.</p>
    pub fn get_minimum_value(&self) -> &::std::option::Option<crate::types::DecimalNumber> {
        &self.minimum_value
    }
    /// <p>The highest value in the column.</p>
    pub fn maximum_value(mut self, input: crate::types::DecimalNumber) -> Self {
        self.maximum_value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The highest value in the column.</p>
    pub fn set_maximum_value(mut self, input: ::std::option::Option<crate::types::DecimalNumber>) -> Self {
        self.maximum_value = input;
        self
    }
    /// <p>The highest value in the column.</p>
    pub fn get_maximum_value(&self) -> &::std::option::Option<crate::types::DecimalNumber> {
        &self.maximum_value
    }
    /// <p>The number of null values in the column.</p>
    /// This field is required.
    pub fn number_of_nulls(mut self, input: i64) -> Self {
        self.number_of_nulls = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of null values in the column.</p>
    pub fn set_number_of_nulls(mut self, input: ::std::option::Option<i64>) -> Self {
        self.number_of_nulls = input;
        self
    }
    /// <p>The number of null values in the column.</p>
    pub fn get_number_of_nulls(&self) -> &::std::option::Option<i64> {
        &self.number_of_nulls
    }
    /// <p>The number of distinct values in a column.</p>
    /// This field is required.
    pub fn number_of_distinct_values(mut self, input: i64) -> Self {
        self.number_of_distinct_values = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of distinct values in a column.</p>
    pub fn set_number_of_distinct_values(mut self, input: ::std::option::Option<i64>) -> Self {
        self.number_of_distinct_values = input;
        self
    }
    /// <p>The number of distinct values in a column.</p>
    pub fn get_number_of_distinct_values(&self) -> &::std::option::Option<i64> {
        &self.number_of_distinct_values
    }
    /// Consumes the builder and constructs a [`DecimalColumnStatisticsData`](crate::types::DecimalColumnStatisticsData).
    pub fn build(self) -> crate::types::DecimalColumnStatisticsData {
        crate::types::DecimalColumnStatisticsData {
            minimum_value: self.minimum_value,
            maximum_value: self.maximum_value,
            number_of_nulls: self.number_of_nulls.unwrap_or_default(),
            number_of_distinct_values: self.number_of_distinct_values.unwrap_or_default(),
        }
    }
}
