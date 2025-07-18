// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Allows filtering on <code>AvailabilityEndDate</code> of a ResaleAuthorization.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResaleAuthorizationAvailabilityEndDateFilter {
    /// <p>Allows filtering on <code>AvailabilityEndDate</code> of a ResaleAuthorization with date range as input</p>
    pub date_range: ::std::option::Option<crate::types::ResaleAuthorizationAvailabilityEndDateFilterDateRange>,
    /// <p>Allows filtering on <code>AvailabilityEndDate</code> of a ResaleAuthorization with date value as input.</p>
    pub value_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ResaleAuthorizationAvailabilityEndDateFilter {
    /// <p>Allows filtering on <code>AvailabilityEndDate</code> of a ResaleAuthorization with date range as input</p>
    pub fn date_range(&self) -> ::std::option::Option<&crate::types::ResaleAuthorizationAvailabilityEndDateFilterDateRange> {
        self.date_range.as_ref()
    }
    /// <p>Allows filtering on <code>AvailabilityEndDate</code> of a ResaleAuthorization with date value as input.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.value_list.is_none()`.
    pub fn value_list(&self) -> &[::std::string::String] {
        self.value_list.as_deref().unwrap_or_default()
    }
}
impl ResaleAuthorizationAvailabilityEndDateFilter {
    /// Creates a new builder-style object to manufacture [`ResaleAuthorizationAvailabilityEndDateFilter`](crate::types::ResaleAuthorizationAvailabilityEndDateFilter).
    pub fn builder() -> crate::types::builders::ResaleAuthorizationAvailabilityEndDateFilterBuilder {
        crate::types::builders::ResaleAuthorizationAvailabilityEndDateFilterBuilder::default()
    }
}

/// A builder for [`ResaleAuthorizationAvailabilityEndDateFilter`](crate::types::ResaleAuthorizationAvailabilityEndDateFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResaleAuthorizationAvailabilityEndDateFilterBuilder {
    pub(crate) date_range: ::std::option::Option<crate::types::ResaleAuthorizationAvailabilityEndDateFilterDateRange>,
    pub(crate) value_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ResaleAuthorizationAvailabilityEndDateFilterBuilder {
    /// <p>Allows filtering on <code>AvailabilityEndDate</code> of a ResaleAuthorization with date range as input</p>
    pub fn date_range(mut self, input: crate::types::ResaleAuthorizationAvailabilityEndDateFilterDateRange) -> Self {
        self.date_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>Allows filtering on <code>AvailabilityEndDate</code> of a ResaleAuthorization with date range as input</p>
    pub fn set_date_range(mut self, input: ::std::option::Option<crate::types::ResaleAuthorizationAvailabilityEndDateFilterDateRange>) -> Self {
        self.date_range = input;
        self
    }
    /// <p>Allows filtering on <code>AvailabilityEndDate</code> of a ResaleAuthorization with date range as input</p>
    pub fn get_date_range(&self) -> &::std::option::Option<crate::types::ResaleAuthorizationAvailabilityEndDateFilterDateRange> {
        &self.date_range
    }
    /// Appends an item to `value_list`.
    ///
    /// To override the contents of this collection use [`set_value_list`](Self::set_value_list).
    ///
    /// <p>Allows filtering on <code>AvailabilityEndDate</code> of a ResaleAuthorization with date value as input.</p>
    pub fn value_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.value_list.unwrap_or_default();
        v.push(input.into());
        self.value_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>Allows filtering on <code>AvailabilityEndDate</code> of a ResaleAuthorization with date value as input.</p>
    pub fn set_value_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.value_list = input;
        self
    }
    /// <p>Allows filtering on <code>AvailabilityEndDate</code> of a ResaleAuthorization with date value as input.</p>
    pub fn get_value_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.value_list
    }
    /// Consumes the builder and constructs a [`ResaleAuthorizationAvailabilityEndDateFilter`](crate::types::ResaleAuthorizationAvailabilityEndDateFilter).
    pub fn build(self) -> crate::types::ResaleAuthorizationAvailabilityEndDateFilter {
        crate::types::ResaleAuthorizationAvailabilityEndDateFilter {
            date_range: self.date_range,
            value_list: self.value_list,
        }
    }
}
