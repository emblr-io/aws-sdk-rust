// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a rotation in an on-call schedule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Rotation {
    /// <p>The Amazon Resource Name (ARN) of the rotation.</p>
    pub rotation_arn: ::std::string::String,
    /// <p>The name of the rotation.</p>
    pub name: ::std::string::String,
    /// <p>The Amazon Resource Names (ARNs) of the contacts assigned to the rotation team.</p>
    pub contact_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The date and time the rotation becomes active.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time zone the rotation’s activity is based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul".</p>
    pub time_zone_id: ::std::option::Option<::std::string::String>,
    /// <p>Information about when an on-call rotation is in effect and how long the rotation period lasts.</p>
    pub recurrence: ::std::option::Option<crate::types::RecurrenceSettings>,
}
impl Rotation {
    /// <p>The Amazon Resource Name (ARN) of the rotation.</p>
    pub fn rotation_arn(&self) -> &str {
        use std::ops::Deref;
        self.rotation_arn.deref()
    }
    /// <p>The name of the rotation.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The Amazon Resource Names (ARNs) of the contacts assigned to the rotation team.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.contact_ids.is_none()`.
    pub fn contact_ids(&self) -> &[::std::string::String] {
        self.contact_ids.as_deref().unwrap_or_default()
    }
    /// <p>The date and time the rotation becomes active.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The time zone the rotation’s activity is based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul".</p>
    pub fn time_zone_id(&self) -> ::std::option::Option<&str> {
        self.time_zone_id.as_deref()
    }
    /// <p>Information about when an on-call rotation is in effect and how long the rotation period lasts.</p>
    pub fn recurrence(&self) -> ::std::option::Option<&crate::types::RecurrenceSettings> {
        self.recurrence.as_ref()
    }
}
impl Rotation {
    /// Creates a new builder-style object to manufacture [`Rotation`](crate::types::Rotation).
    pub fn builder() -> crate::types::builders::RotationBuilder {
        crate::types::builders::RotationBuilder::default()
    }
}

/// A builder for [`Rotation`](crate::types::Rotation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RotationBuilder {
    pub(crate) rotation_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) contact_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) time_zone_id: ::std::option::Option<::std::string::String>,
    pub(crate) recurrence: ::std::option::Option<crate::types::RecurrenceSettings>,
}
impl RotationBuilder {
    /// <p>The Amazon Resource Name (ARN) of the rotation.</p>
    /// This field is required.
    pub fn rotation_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rotation_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the rotation.</p>
    pub fn set_rotation_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rotation_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the rotation.</p>
    pub fn get_rotation_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.rotation_arn
    }
    /// <p>The name of the rotation.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the rotation.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the rotation.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `contact_ids`.
    ///
    /// To override the contents of this collection use [`set_contact_ids`](Self::set_contact_ids).
    ///
    /// <p>The Amazon Resource Names (ARNs) of the contacts assigned to the rotation team.</p>
    pub fn contact_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.contact_ids.unwrap_or_default();
        v.push(input.into());
        self.contact_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Resource Names (ARNs) of the contacts assigned to the rotation team.</p>
    pub fn set_contact_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.contact_ids = input;
        self
    }
    /// <p>The Amazon Resource Names (ARNs) of the contacts assigned to the rotation team.</p>
    pub fn get_contact_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.contact_ids
    }
    /// <p>The date and time the rotation becomes active.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the rotation becomes active.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The date and time the rotation becomes active.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The time zone the rotation’s activity is based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul".</p>
    pub fn time_zone_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.time_zone_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time zone the rotation’s activity is based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul".</p>
    pub fn set_time_zone_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.time_zone_id = input;
        self
    }
    /// <p>The time zone the rotation’s activity is based on, in Internet Assigned Numbers Authority (IANA) format. For example: "America/Los_Angeles", "UTC", or "Asia/Seoul".</p>
    pub fn get_time_zone_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.time_zone_id
    }
    /// <p>Information about when an on-call rotation is in effect and how long the rotation period lasts.</p>
    pub fn recurrence(mut self, input: crate::types::RecurrenceSettings) -> Self {
        self.recurrence = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about when an on-call rotation is in effect and how long the rotation period lasts.</p>
    pub fn set_recurrence(mut self, input: ::std::option::Option<crate::types::RecurrenceSettings>) -> Self {
        self.recurrence = input;
        self
    }
    /// <p>Information about when an on-call rotation is in effect and how long the rotation period lasts.</p>
    pub fn get_recurrence(&self) -> &::std::option::Option<crate::types::RecurrenceSettings> {
        &self.recurrence
    }
    /// Consumes the builder and constructs a [`Rotation`](crate::types::Rotation).
    /// This method will fail if any of the following fields are not set:
    /// - [`rotation_arn`](crate::types::builders::RotationBuilder::rotation_arn)
    /// - [`name`](crate::types::builders::RotationBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::Rotation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Rotation {
            rotation_arn: self.rotation_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "rotation_arn",
                    "rotation_arn was not specified but it is required when building Rotation",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building Rotation",
                )
            })?,
            contact_ids: self.contact_ids,
            start_time: self.start_time,
            time_zone_id: self.time_zone_id,
            recurrence: self.recurrence,
        })
    }
}
