// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The number of managed nodes found for each patch severity level defined in the request filter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SeveritySummary {
    /// <p>The total number of resources or compliance items that have a severity level of <code>Critical</code>. Critical severity is determined by the organization that published the compliance items.</p>
    pub critical_count: i32,
    /// <p>The total number of resources or compliance items that have a severity level of high. High severity is determined by the organization that published the compliance items.</p>
    pub high_count: i32,
    /// <p>The total number of resources or compliance items that have a severity level of medium. Medium severity is determined by the organization that published the compliance items.</p>
    pub medium_count: i32,
    /// <p>The total number of resources or compliance items that have a severity level of low. Low severity is determined by the organization that published the compliance items.</p>
    pub low_count: i32,
    /// <p>The total number of resources or compliance items that have a severity level of informational. Informational severity is determined by the organization that published the compliance items.</p>
    pub informational_count: i32,
    /// <p>The total number of resources or compliance items that have a severity level of unspecified. Unspecified severity is determined by the organization that published the compliance items.</p>
    pub unspecified_count: i32,
}
impl SeveritySummary {
    /// <p>The total number of resources or compliance items that have a severity level of <code>Critical</code>. Critical severity is determined by the organization that published the compliance items.</p>
    pub fn critical_count(&self) -> i32 {
        self.critical_count
    }
    /// <p>The total number of resources or compliance items that have a severity level of high. High severity is determined by the organization that published the compliance items.</p>
    pub fn high_count(&self) -> i32 {
        self.high_count
    }
    /// <p>The total number of resources or compliance items that have a severity level of medium. Medium severity is determined by the organization that published the compliance items.</p>
    pub fn medium_count(&self) -> i32 {
        self.medium_count
    }
    /// <p>The total number of resources or compliance items that have a severity level of low. Low severity is determined by the organization that published the compliance items.</p>
    pub fn low_count(&self) -> i32 {
        self.low_count
    }
    /// <p>The total number of resources or compliance items that have a severity level of informational. Informational severity is determined by the organization that published the compliance items.</p>
    pub fn informational_count(&self) -> i32 {
        self.informational_count
    }
    /// <p>The total number of resources or compliance items that have a severity level of unspecified. Unspecified severity is determined by the organization that published the compliance items.</p>
    pub fn unspecified_count(&self) -> i32 {
        self.unspecified_count
    }
}
impl SeveritySummary {
    /// Creates a new builder-style object to manufacture [`SeveritySummary`](crate::types::SeveritySummary).
    pub fn builder() -> crate::types::builders::SeveritySummaryBuilder {
        crate::types::builders::SeveritySummaryBuilder::default()
    }
}

/// A builder for [`SeveritySummary`](crate::types::SeveritySummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SeveritySummaryBuilder {
    pub(crate) critical_count: ::std::option::Option<i32>,
    pub(crate) high_count: ::std::option::Option<i32>,
    pub(crate) medium_count: ::std::option::Option<i32>,
    pub(crate) low_count: ::std::option::Option<i32>,
    pub(crate) informational_count: ::std::option::Option<i32>,
    pub(crate) unspecified_count: ::std::option::Option<i32>,
}
impl SeveritySummaryBuilder {
    /// <p>The total number of resources or compliance items that have a severity level of <code>Critical</code>. Critical severity is determined by the organization that published the compliance items.</p>
    pub fn critical_count(mut self, input: i32) -> Self {
        self.critical_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of resources or compliance items that have a severity level of <code>Critical</code>. Critical severity is determined by the organization that published the compliance items.</p>
    pub fn set_critical_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.critical_count = input;
        self
    }
    /// <p>The total number of resources or compliance items that have a severity level of <code>Critical</code>. Critical severity is determined by the organization that published the compliance items.</p>
    pub fn get_critical_count(&self) -> &::std::option::Option<i32> {
        &self.critical_count
    }
    /// <p>The total number of resources or compliance items that have a severity level of high. High severity is determined by the organization that published the compliance items.</p>
    pub fn high_count(mut self, input: i32) -> Self {
        self.high_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of resources or compliance items that have a severity level of high. High severity is determined by the organization that published the compliance items.</p>
    pub fn set_high_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.high_count = input;
        self
    }
    /// <p>The total number of resources or compliance items that have a severity level of high. High severity is determined by the organization that published the compliance items.</p>
    pub fn get_high_count(&self) -> &::std::option::Option<i32> {
        &self.high_count
    }
    /// <p>The total number of resources or compliance items that have a severity level of medium. Medium severity is determined by the organization that published the compliance items.</p>
    pub fn medium_count(mut self, input: i32) -> Self {
        self.medium_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of resources or compliance items that have a severity level of medium. Medium severity is determined by the organization that published the compliance items.</p>
    pub fn set_medium_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.medium_count = input;
        self
    }
    /// <p>The total number of resources or compliance items that have a severity level of medium. Medium severity is determined by the organization that published the compliance items.</p>
    pub fn get_medium_count(&self) -> &::std::option::Option<i32> {
        &self.medium_count
    }
    /// <p>The total number of resources or compliance items that have a severity level of low. Low severity is determined by the organization that published the compliance items.</p>
    pub fn low_count(mut self, input: i32) -> Self {
        self.low_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of resources or compliance items that have a severity level of low. Low severity is determined by the organization that published the compliance items.</p>
    pub fn set_low_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.low_count = input;
        self
    }
    /// <p>The total number of resources or compliance items that have a severity level of low. Low severity is determined by the organization that published the compliance items.</p>
    pub fn get_low_count(&self) -> &::std::option::Option<i32> {
        &self.low_count
    }
    /// <p>The total number of resources or compliance items that have a severity level of informational. Informational severity is determined by the organization that published the compliance items.</p>
    pub fn informational_count(mut self, input: i32) -> Self {
        self.informational_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of resources or compliance items that have a severity level of informational. Informational severity is determined by the organization that published the compliance items.</p>
    pub fn set_informational_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.informational_count = input;
        self
    }
    /// <p>The total number of resources or compliance items that have a severity level of informational. Informational severity is determined by the organization that published the compliance items.</p>
    pub fn get_informational_count(&self) -> &::std::option::Option<i32> {
        &self.informational_count
    }
    /// <p>The total number of resources or compliance items that have a severity level of unspecified. Unspecified severity is determined by the organization that published the compliance items.</p>
    pub fn unspecified_count(mut self, input: i32) -> Self {
        self.unspecified_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of resources or compliance items that have a severity level of unspecified. Unspecified severity is determined by the organization that published the compliance items.</p>
    pub fn set_unspecified_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.unspecified_count = input;
        self
    }
    /// <p>The total number of resources or compliance items that have a severity level of unspecified. Unspecified severity is determined by the organization that published the compliance items.</p>
    pub fn get_unspecified_count(&self) -> &::std::option::Option<i32> {
        &self.unspecified_count
    }
    /// Consumes the builder and constructs a [`SeveritySummary`](crate::types::SeveritySummary).
    pub fn build(self) -> crate::types::SeveritySummary {
        crate::types::SeveritySummary {
            critical_count: self.critical_count.unwrap_or_default(),
            high_count: self.high_count.unwrap_or_default(),
            medium_count: self.medium_count.unwrap_or_default(),
            low_count: self.low_count.unwrap_or_default(),
            informational_count: self.informational_count.unwrap_or_default(),
            unspecified_count: self.unspecified_count.unwrap_or_default(),
        }
    }
}
