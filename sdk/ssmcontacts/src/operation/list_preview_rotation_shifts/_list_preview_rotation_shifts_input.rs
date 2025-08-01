// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPreviewRotationShiftsInput {
    /// <p>The date and time a rotation would begin. The first shift is calculated from this date and time.</p>
    pub rotation_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Used to filter the range of calculated shifts before sending the response back to the user.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time a rotation shift would end.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The contacts that would be assigned to a rotation.</p>
    pub members: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The time zone the rotation’s activity would be based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul".</p>
    pub time_zone_id: ::std::option::Option<::std::string::String>,
    /// <p>Information about how long a rotation would last before restarting at the beginning of the shift order.</p>
    pub recurrence: ::std::option::Option<crate::types::RecurrenceSettings>,
    /// <p>Information about changes that would be made in a rotation override.</p>
    pub overrides: ::std::option::Option<::std::vec::Vec<crate::types::PreviewOverride>>,
    /// <p>A token to start the list. This token is used to get the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to return for this call. The call also returns a token that can be specified in a subsequent call to get the next set of results.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListPreviewRotationShiftsInput {
    /// <p>The date and time a rotation would begin. The first shift is calculated from this date and time.</p>
    pub fn rotation_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.rotation_start_time.as_ref()
    }
    /// <p>Used to filter the range of calculated shifts before sending the response back to the user.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The date and time a rotation shift would end.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>The contacts that would be assigned to a rotation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.members.is_none()`.
    pub fn members(&self) -> &[::std::string::String] {
        self.members.as_deref().unwrap_or_default()
    }
    /// <p>The time zone the rotation’s activity would be based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul".</p>
    pub fn time_zone_id(&self) -> ::std::option::Option<&str> {
        self.time_zone_id.as_deref()
    }
    /// <p>Information about how long a rotation would last before restarting at the beginning of the shift order.</p>
    pub fn recurrence(&self) -> ::std::option::Option<&crate::types::RecurrenceSettings> {
        self.recurrence.as_ref()
    }
    /// <p>Information about changes that would be made in a rotation override.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.overrides.is_none()`.
    pub fn overrides(&self) -> &[crate::types::PreviewOverride] {
        self.overrides.as_deref().unwrap_or_default()
    }
    /// <p>A token to start the list. This token is used to get the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that can be specified in a subsequent call to get the next set of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListPreviewRotationShiftsInput {
    /// Creates a new builder-style object to manufacture [`ListPreviewRotationShiftsInput`](crate::operation::list_preview_rotation_shifts::ListPreviewRotationShiftsInput).
    pub fn builder() -> crate::operation::list_preview_rotation_shifts::builders::ListPreviewRotationShiftsInputBuilder {
        crate::operation::list_preview_rotation_shifts::builders::ListPreviewRotationShiftsInputBuilder::default()
    }
}

/// A builder for [`ListPreviewRotationShiftsInput`](crate::operation::list_preview_rotation_shifts::ListPreviewRotationShiftsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPreviewRotationShiftsInputBuilder {
    pub(crate) rotation_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) members: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) time_zone_id: ::std::option::Option<::std::string::String>,
    pub(crate) recurrence: ::std::option::Option<crate::types::RecurrenceSettings>,
    pub(crate) overrides: ::std::option::Option<::std::vec::Vec<crate::types::PreviewOverride>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListPreviewRotationShiftsInputBuilder {
    /// <p>The date and time a rotation would begin. The first shift is calculated from this date and time.</p>
    pub fn rotation_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.rotation_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time a rotation would begin. The first shift is calculated from this date and time.</p>
    pub fn set_rotation_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.rotation_start_time = input;
        self
    }
    /// <p>The date and time a rotation would begin. The first shift is calculated from this date and time.</p>
    pub fn get_rotation_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.rotation_start_time
    }
    /// <p>Used to filter the range of calculated shifts before sending the response back to the user.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Used to filter the range of calculated shifts before sending the response back to the user.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>Used to filter the range of calculated shifts before sending the response back to the user.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The date and time a rotation shift would end.</p>
    /// This field is required.
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time a rotation shift would end.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The date and time a rotation shift would end.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// Appends an item to `members`.
    ///
    /// To override the contents of this collection use [`set_members`](Self::set_members).
    ///
    /// <p>The contacts that would be assigned to a rotation.</p>
    pub fn members(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.members.unwrap_or_default();
        v.push(input.into());
        self.members = ::std::option::Option::Some(v);
        self
    }
    /// <p>The contacts that would be assigned to a rotation.</p>
    pub fn set_members(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.members = input;
        self
    }
    /// <p>The contacts that would be assigned to a rotation.</p>
    pub fn get_members(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.members
    }
    /// <p>The time zone the rotation’s activity would be based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul".</p>
    /// This field is required.
    pub fn time_zone_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.time_zone_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time zone the rotation’s activity would be based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul".</p>
    pub fn set_time_zone_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.time_zone_id = input;
        self
    }
    /// <p>The time zone the rotation’s activity would be based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul".</p>
    pub fn get_time_zone_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.time_zone_id
    }
    /// <p>Information about how long a rotation would last before restarting at the beginning of the shift order.</p>
    /// This field is required.
    pub fn recurrence(mut self, input: crate::types::RecurrenceSettings) -> Self {
        self.recurrence = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about how long a rotation would last before restarting at the beginning of the shift order.</p>
    pub fn set_recurrence(mut self, input: ::std::option::Option<crate::types::RecurrenceSettings>) -> Self {
        self.recurrence = input;
        self
    }
    /// <p>Information about how long a rotation would last before restarting at the beginning of the shift order.</p>
    pub fn get_recurrence(&self) -> &::std::option::Option<crate::types::RecurrenceSettings> {
        &self.recurrence
    }
    /// Appends an item to `overrides`.
    ///
    /// To override the contents of this collection use [`set_overrides`](Self::set_overrides).
    ///
    /// <p>Information about changes that would be made in a rotation override.</p>
    pub fn overrides(mut self, input: crate::types::PreviewOverride) -> Self {
        let mut v = self.overrides.unwrap_or_default();
        v.push(input);
        self.overrides = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about changes that would be made in a rotation override.</p>
    pub fn set_overrides(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PreviewOverride>>) -> Self {
        self.overrides = input;
        self
    }
    /// <p>Information about changes that would be made in a rotation override.</p>
    pub fn get_overrides(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PreviewOverride>> {
        &self.overrides
    }
    /// <p>A token to start the list. This token is used to get the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to start the list. This token is used to get the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to start the list. This token is used to get the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that can be specified in a subsequent call to get the next set of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that can be specified in a subsequent call to get the next set of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to return for this call. The call also returns a token that can be specified in a subsequent call to get the next set of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListPreviewRotationShiftsInput`](crate::operation::list_preview_rotation_shifts::ListPreviewRotationShiftsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_preview_rotation_shifts::ListPreviewRotationShiftsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_preview_rotation_shifts::ListPreviewRotationShiftsInput {
            rotation_start_time: self.rotation_start_time,
            start_time: self.start_time,
            end_time: self.end_time,
            members: self.members,
            time_zone_id: self.time_zone_id,
            recurrence: self.recurrence,
            overrides: self.overrides,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
