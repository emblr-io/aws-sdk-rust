// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The settings that determine how and when MediaTailor places prefetched ads into upcoming ad breaks for recurring prefetch scedules.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecurringConsumption {
    /// <p>The number of seconds that an ad is available for insertion after it was prefetched.</p>
    pub retrieved_ad_expiration_seconds: ::std::option::Option<i32>,
    /// <p>The configuration for the dynamic variables that determine which ad breaks that MediaTailor inserts prefetched ads in.</p>
    pub avail_matching_criteria: ::std::option::Option<::std::vec::Vec<crate::types::AvailMatchingCriteria>>,
}
impl RecurringConsumption {
    /// <p>The number of seconds that an ad is available for insertion after it was prefetched.</p>
    pub fn retrieved_ad_expiration_seconds(&self) -> ::std::option::Option<i32> {
        self.retrieved_ad_expiration_seconds
    }
    /// <p>The configuration for the dynamic variables that determine which ad breaks that MediaTailor inserts prefetched ads in.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.avail_matching_criteria.is_none()`.
    pub fn avail_matching_criteria(&self) -> &[crate::types::AvailMatchingCriteria] {
        self.avail_matching_criteria.as_deref().unwrap_or_default()
    }
}
impl RecurringConsumption {
    /// Creates a new builder-style object to manufacture [`RecurringConsumption`](crate::types::RecurringConsumption).
    pub fn builder() -> crate::types::builders::RecurringConsumptionBuilder {
        crate::types::builders::RecurringConsumptionBuilder::default()
    }
}

/// A builder for [`RecurringConsumption`](crate::types::RecurringConsumption).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecurringConsumptionBuilder {
    pub(crate) retrieved_ad_expiration_seconds: ::std::option::Option<i32>,
    pub(crate) avail_matching_criteria: ::std::option::Option<::std::vec::Vec<crate::types::AvailMatchingCriteria>>,
}
impl RecurringConsumptionBuilder {
    /// <p>The number of seconds that an ad is available for insertion after it was prefetched.</p>
    pub fn retrieved_ad_expiration_seconds(mut self, input: i32) -> Self {
        self.retrieved_ad_expiration_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of seconds that an ad is available for insertion after it was prefetched.</p>
    pub fn set_retrieved_ad_expiration_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.retrieved_ad_expiration_seconds = input;
        self
    }
    /// <p>The number of seconds that an ad is available for insertion after it was prefetched.</p>
    pub fn get_retrieved_ad_expiration_seconds(&self) -> &::std::option::Option<i32> {
        &self.retrieved_ad_expiration_seconds
    }
    /// Appends an item to `avail_matching_criteria`.
    ///
    /// To override the contents of this collection use [`set_avail_matching_criteria`](Self::set_avail_matching_criteria).
    ///
    /// <p>The configuration for the dynamic variables that determine which ad breaks that MediaTailor inserts prefetched ads in.</p>
    pub fn avail_matching_criteria(mut self, input: crate::types::AvailMatchingCriteria) -> Self {
        let mut v = self.avail_matching_criteria.unwrap_or_default();
        v.push(input);
        self.avail_matching_criteria = ::std::option::Option::Some(v);
        self
    }
    /// <p>The configuration for the dynamic variables that determine which ad breaks that MediaTailor inserts prefetched ads in.</p>
    pub fn set_avail_matching_criteria(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AvailMatchingCriteria>>) -> Self {
        self.avail_matching_criteria = input;
        self
    }
    /// <p>The configuration for the dynamic variables that determine which ad breaks that MediaTailor inserts prefetched ads in.</p>
    pub fn get_avail_matching_criteria(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AvailMatchingCriteria>> {
        &self.avail_matching_criteria
    }
    /// Consumes the builder and constructs a [`RecurringConsumption`](crate::types::RecurringConsumption).
    pub fn build(self) -> crate::types::RecurringConsumption {
        crate::types::RecurringConsumption {
            retrieved_ad_expiration_seconds: self.retrieved_ad_expiration_seconds,
            avail_matching_criteria: self.avail_matching_criteria,
        }
    }
}
