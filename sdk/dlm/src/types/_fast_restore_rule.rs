// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p><b>\[Custom snapshot policies only\]</b> Specifies a rule for enabling fast snapshot restore for snapshots created by snapshot policies. You can enable fast snapshot restore based on either a count or a time interval.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FastRestoreRule {
    /// <p>The number of snapshots to be enabled with fast snapshot restore.</p>
    pub count: ::std::option::Option<i32>,
    /// <p>The amount of time to enable fast snapshot restore. The maximum is 100 years. This is equivalent to 1200 months, 5200 weeks, or 36500 days.</p>
    pub interval: ::std::option::Option<i32>,
    /// <p>The unit of time for enabling fast snapshot restore.</p>
    pub interval_unit: ::std::option::Option<crate::types::RetentionIntervalUnitValues>,
    /// <p>The Availability Zones in which to enable fast snapshot restore.</p>
    pub availability_zones: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl FastRestoreRule {
    /// <p>The number of snapshots to be enabled with fast snapshot restore.</p>
    pub fn count(&self) -> ::std::option::Option<i32> {
        self.count
    }
    /// <p>The amount of time to enable fast snapshot restore. The maximum is 100 years. This is equivalent to 1200 months, 5200 weeks, or 36500 days.</p>
    pub fn interval(&self) -> ::std::option::Option<i32> {
        self.interval
    }
    /// <p>The unit of time for enabling fast snapshot restore.</p>
    pub fn interval_unit(&self) -> ::std::option::Option<&crate::types::RetentionIntervalUnitValues> {
        self.interval_unit.as_ref()
    }
    /// <p>The Availability Zones in which to enable fast snapshot restore.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.availability_zones.is_none()`.
    pub fn availability_zones(&self) -> &[::std::string::String] {
        self.availability_zones.as_deref().unwrap_or_default()
    }
}
impl FastRestoreRule {
    /// Creates a new builder-style object to manufacture [`FastRestoreRule`](crate::types::FastRestoreRule).
    pub fn builder() -> crate::types::builders::FastRestoreRuleBuilder {
        crate::types::builders::FastRestoreRuleBuilder::default()
    }
}

/// A builder for [`FastRestoreRule`](crate::types::FastRestoreRule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FastRestoreRuleBuilder {
    pub(crate) count: ::std::option::Option<i32>,
    pub(crate) interval: ::std::option::Option<i32>,
    pub(crate) interval_unit: ::std::option::Option<crate::types::RetentionIntervalUnitValues>,
    pub(crate) availability_zones: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl FastRestoreRuleBuilder {
    /// <p>The number of snapshots to be enabled with fast snapshot restore.</p>
    pub fn count(mut self, input: i32) -> Self {
        self.count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of snapshots to be enabled with fast snapshot restore.</p>
    pub fn set_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.count = input;
        self
    }
    /// <p>The number of snapshots to be enabled with fast snapshot restore.</p>
    pub fn get_count(&self) -> &::std::option::Option<i32> {
        &self.count
    }
    /// <p>The amount of time to enable fast snapshot restore. The maximum is 100 years. This is equivalent to 1200 months, 5200 weeks, or 36500 days.</p>
    pub fn interval(mut self, input: i32) -> Self {
        self.interval = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time to enable fast snapshot restore. The maximum is 100 years. This is equivalent to 1200 months, 5200 weeks, or 36500 days.</p>
    pub fn set_interval(mut self, input: ::std::option::Option<i32>) -> Self {
        self.interval = input;
        self
    }
    /// <p>The amount of time to enable fast snapshot restore. The maximum is 100 years. This is equivalent to 1200 months, 5200 weeks, or 36500 days.</p>
    pub fn get_interval(&self) -> &::std::option::Option<i32> {
        &self.interval
    }
    /// <p>The unit of time for enabling fast snapshot restore.</p>
    pub fn interval_unit(mut self, input: crate::types::RetentionIntervalUnitValues) -> Self {
        self.interval_unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The unit of time for enabling fast snapshot restore.</p>
    pub fn set_interval_unit(mut self, input: ::std::option::Option<crate::types::RetentionIntervalUnitValues>) -> Self {
        self.interval_unit = input;
        self
    }
    /// <p>The unit of time for enabling fast snapshot restore.</p>
    pub fn get_interval_unit(&self) -> &::std::option::Option<crate::types::RetentionIntervalUnitValues> {
        &self.interval_unit
    }
    /// Appends an item to `availability_zones`.
    ///
    /// To override the contents of this collection use [`set_availability_zones`](Self::set_availability_zones).
    ///
    /// <p>The Availability Zones in which to enable fast snapshot restore.</p>
    pub fn availability_zones(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.availability_zones.unwrap_or_default();
        v.push(input.into());
        self.availability_zones = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Availability Zones in which to enable fast snapshot restore.</p>
    pub fn set_availability_zones(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.availability_zones = input;
        self
    }
    /// <p>The Availability Zones in which to enable fast snapshot restore.</p>
    pub fn get_availability_zones(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.availability_zones
    }
    /// Consumes the builder and constructs a [`FastRestoreRule`](crate::types::FastRestoreRule).
    pub fn build(self) -> crate::types::FastRestoreRule {
        crate::types::FastRestoreRule {
            count: self.count,
            interval: self.interval,
            interval_unit: self.interval_unit,
            availability_zones: self.availability_zones,
        }
    }
}
