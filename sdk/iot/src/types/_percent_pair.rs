// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the percentile and percentile value.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PercentPair {
    /// <p>The percentile.</p>
    pub percent: f64,
    /// <p>The value of the percentile.</p>
    pub value: f64,
}
impl PercentPair {
    /// <p>The percentile.</p>
    pub fn percent(&self) -> f64 {
        self.percent
    }
    /// <p>The value of the percentile.</p>
    pub fn value(&self) -> f64 {
        self.value
    }
}
impl PercentPair {
    /// Creates a new builder-style object to manufacture [`PercentPair`](crate::types::PercentPair).
    pub fn builder() -> crate::types::builders::PercentPairBuilder {
        crate::types::builders::PercentPairBuilder::default()
    }
}

/// A builder for [`PercentPair`](crate::types::PercentPair).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PercentPairBuilder {
    pub(crate) percent: ::std::option::Option<f64>,
    pub(crate) value: ::std::option::Option<f64>,
}
impl PercentPairBuilder {
    /// <p>The percentile.</p>
    pub fn percent(mut self, input: f64) -> Self {
        self.percent = ::std::option::Option::Some(input);
        self
    }
    /// <p>The percentile.</p>
    pub fn set_percent(mut self, input: ::std::option::Option<f64>) -> Self {
        self.percent = input;
        self
    }
    /// <p>The percentile.</p>
    pub fn get_percent(&self) -> &::std::option::Option<f64> {
        &self.percent
    }
    /// <p>The value of the percentile.</p>
    pub fn value(mut self, input: f64) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value of the percentile.</p>
    pub fn set_value(mut self, input: ::std::option::Option<f64>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the percentile.</p>
    pub fn get_value(&self) -> &::std::option::Option<f64> {
        &self.value
    }
    /// Consumes the builder and constructs a [`PercentPair`](crate::types::PercentPair).
    pub fn build(self) -> crate::types::PercentPair {
        crate::types::PercentPair {
            percent: self.percent.unwrap_or_default(),
            value: self.value.unwrap_or_default(),
        }
    }
}
