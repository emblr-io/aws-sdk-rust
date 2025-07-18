// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>How long, in days, message data is kept.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RetentionPeriod {
    /// <p>If true, message data is kept indefinitely.</p>
    pub unlimited: bool,
    /// <p>The number of days that message data is kept. The <code>unlimited</code> parameter must be false.</p>
    pub number_of_days: ::std::option::Option<i32>,
}
impl RetentionPeriod {
    /// <p>If true, message data is kept indefinitely.</p>
    pub fn unlimited(&self) -> bool {
        self.unlimited
    }
    /// <p>The number of days that message data is kept. The <code>unlimited</code> parameter must be false.</p>
    pub fn number_of_days(&self) -> ::std::option::Option<i32> {
        self.number_of_days
    }
}
impl RetentionPeriod {
    /// Creates a new builder-style object to manufacture [`RetentionPeriod`](crate::types::RetentionPeriod).
    pub fn builder() -> crate::types::builders::RetentionPeriodBuilder {
        crate::types::builders::RetentionPeriodBuilder::default()
    }
}

/// A builder for [`RetentionPeriod`](crate::types::RetentionPeriod).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RetentionPeriodBuilder {
    pub(crate) unlimited: ::std::option::Option<bool>,
    pub(crate) number_of_days: ::std::option::Option<i32>,
}
impl RetentionPeriodBuilder {
    /// <p>If true, message data is kept indefinitely.</p>
    pub fn unlimited(mut self, input: bool) -> Self {
        self.unlimited = ::std::option::Option::Some(input);
        self
    }
    /// <p>If true, message data is kept indefinitely.</p>
    pub fn set_unlimited(mut self, input: ::std::option::Option<bool>) -> Self {
        self.unlimited = input;
        self
    }
    /// <p>If true, message data is kept indefinitely.</p>
    pub fn get_unlimited(&self) -> &::std::option::Option<bool> {
        &self.unlimited
    }
    /// <p>The number of days that message data is kept. The <code>unlimited</code> parameter must be false.</p>
    pub fn number_of_days(mut self, input: i32) -> Self {
        self.number_of_days = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of days that message data is kept. The <code>unlimited</code> parameter must be false.</p>
    pub fn set_number_of_days(mut self, input: ::std::option::Option<i32>) -> Self {
        self.number_of_days = input;
        self
    }
    /// <p>The number of days that message data is kept. The <code>unlimited</code> parameter must be false.</p>
    pub fn get_number_of_days(&self) -> &::std::option::Option<i32> {
        &self.number_of_days
    }
    /// Consumes the builder and constructs a [`RetentionPeriod`](crate::types::RetentionPeriod).
    pub fn build(self) -> crate::types::RetentionPeriod {
        crate::types::RetentionPeriod {
            unlimited: self.unlimited.unwrap_or_default(),
            number_of_days: self.number_of_days,
        }
    }
}
