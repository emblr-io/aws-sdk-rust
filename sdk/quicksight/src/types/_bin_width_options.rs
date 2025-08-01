// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The options that determine the bin width of a histogram.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BinWidthOptions {
    /// <p>The options that determine the bin width value.</p>
    pub value: ::std::option::Option<f64>,
    /// <p>The options that determine the bin count limit.</p>
    pub bin_count_limit: ::std::option::Option<i64>,
}
impl BinWidthOptions {
    /// <p>The options that determine the bin width value.</p>
    pub fn value(&self) -> ::std::option::Option<f64> {
        self.value
    }
    /// <p>The options that determine the bin count limit.</p>
    pub fn bin_count_limit(&self) -> ::std::option::Option<i64> {
        self.bin_count_limit
    }
}
impl BinWidthOptions {
    /// Creates a new builder-style object to manufacture [`BinWidthOptions`](crate::types::BinWidthOptions).
    pub fn builder() -> crate::types::builders::BinWidthOptionsBuilder {
        crate::types::builders::BinWidthOptionsBuilder::default()
    }
}

/// A builder for [`BinWidthOptions`](crate::types::BinWidthOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BinWidthOptionsBuilder {
    pub(crate) value: ::std::option::Option<f64>,
    pub(crate) bin_count_limit: ::std::option::Option<i64>,
}
impl BinWidthOptionsBuilder {
    /// <p>The options that determine the bin width value.</p>
    pub fn value(mut self, input: f64) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options that determine the bin width value.</p>
    pub fn set_value(mut self, input: ::std::option::Option<f64>) -> Self {
        self.value = input;
        self
    }
    /// <p>The options that determine the bin width value.</p>
    pub fn get_value(&self) -> &::std::option::Option<f64> {
        &self.value
    }
    /// <p>The options that determine the bin count limit.</p>
    pub fn bin_count_limit(mut self, input: i64) -> Self {
        self.bin_count_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options that determine the bin count limit.</p>
    pub fn set_bin_count_limit(mut self, input: ::std::option::Option<i64>) -> Self {
        self.bin_count_limit = input;
        self
    }
    /// <p>The options that determine the bin count limit.</p>
    pub fn get_bin_count_limit(&self) -> &::std::option::Option<i64> {
        &self.bin_count_limit
    }
    /// Consumes the builder and constructs a [`BinWidthOptions`](crate::types::BinWidthOptions).
    pub fn build(self) -> crate::types::BinWidthOptions {
        crate::types::BinWidthOptions {
            value: self.value,
            bin_count_limit: self.bin_count_limit,
        }
    }
}
