// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeOrganizationOverviewInput {
    /// <p>The start of the time range passed in. The start time granularity is at the day level. The floor of the start time is used. Returned information occurred after this day.</p>
    pub from_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The end of the time range passed in. The start time granularity is at the day level. The floor of the start time is used. Returned information occurred before this day. If this is not specified, then the current day is used.</p>
    pub to_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The ID of the Amazon Web Services account.</p>
    pub account_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The ID of the organizational unit.</p>
    pub organizational_unit_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeOrganizationOverviewInput {
    /// <p>The start of the time range passed in. The start time granularity is at the day level. The floor of the start time is used. Returned information occurred after this day.</p>
    pub fn from_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.from_time.as_ref()
    }
    /// <p>The end of the time range passed in. The start time granularity is at the day level. The floor of the start time is used. Returned information occurred before this day. If this is not specified, then the current day is used.</p>
    pub fn to_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.to_time.as_ref()
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.account_ids.is_none()`.
    pub fn account_ids(&self) -> &[::std::string::String] {
        self.account_ids.as_deref().unwrap_or_default()
    }
    /// <p>The ID of the organizational unit.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.organizational_unit_ids.is_none()`.
    pub fn organizational_unit_ids(&self) -> &[::std::string::String] {
        self.organizational_unit_ids.as_deref().unwrap_or_default()
    }
}
impl DescribeOrganizationOverviewInput {
    /// Creates a new builder-style object to manufacture [`DescribeOrganizationOverviewInput`](crate::operation::describe_organization_overview::DescribeOrganizationOverviewInput).
    pub fn builder() -> crate::operation::describe_organization_overview::builders::DescribeOrganizationOverviewInputBuilder {
        crate::operation::describe_organization_overview::builders::DescribeOrganizationOverviewInputBuilder::default()
    }
}

/// A builder for [`DescribeOrganizationOverviewInput`](crate::operation::describe_organization_overview::DescribeOrganizationOverviewInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeOrganizationOverviewInputBuilder {
    pub(crate) from_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) to_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) account_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) organizational_unit_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeOrganizationOverviewInputBuilder {
    /// <p>The start of the time range passed in. The start time granularity is at the day level. The floor of the start time is used. Returned information occurred after this day.</p>
    /// This field is required.
    pub fn from_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.from_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start of the time range passed in. The start time granularity is at the day level. The floor of the start time is used. Returned information occurred after this day.</p>
    pub fn set_from_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.from_time = input;
        self
    }
    /// <p>The start of the time range passed in. The start time granularity is at the day level. The floor of the start time is used. Returned information occurred after this day.</p>
    pub fn get_from_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.from_time
    }
    /// <p>The end of the time range passed in. The start time granularity is at the day level. The floor of the start time is used. Returned information occurred before this day. If this is not specified, then the current day is used.</p>
    pub fn to_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.to_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The end of the time range passed in. The start time granularity is at the day level. The floor of the start time is used. Returned information occurred before this day. If this is not specified, then the current day is used.</p>
    pub fn set_to_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.to_time = input;
        self
    }
    /// <p>The end of the time range passed in. The start time granularity is at the day level. The floor of the start time is used. Returned information occurred before this day. If this is not specified, then the current day is used.</p>
    pub fn get_to_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.to_time
    }
    /// Appends an item to `account_ids`.
    ///
    /// To override the contents of this collection use [`set_account_ids`](Self::set_account_ids).
    ///
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn account_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.account_ids.unwrap_or_default();
        v.push(input.into());
        self.account_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn set_account_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.account_ids = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn get_account_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.account_ids
    }
    /// Appends an item to `organizational_unit_ids`.
    ///
    /// To override the contents of this collection use [`set_organizational_unit_ids`](Self::set_organizational_unit_ids).
    ///
    /// <p>The ID of the organizational unit.</p>
    pub fn organizational_unit_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.organizational_unit_ids.unwrap_or_default();
        v.push(input.into());
        self.organizational_unit_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ID of the organizational unit.</p>
    pub fn set_organizational_unit_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.organizational_unit_ids = input;
        self
    }
    /// <p>The ID of the organizational unit.</p>
    pub fn get_organizational_unit_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.organizational_unit_ids
    }
    /// Consumes the builder and constructs a [`DescribeOrganizationOverviewInput`](crate::operation::describe_organization_overview::DescribeOrganizationOverviewInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_organization_overview::DescribeOrganizationOverviewInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_organization_overview::DescribeOrganizationOverviewInput {
            from_time: self.from_time,
            to_time: self.to_time,
            account_ids: self.account_ids,
            organizational_unit_ids: self.organizational_unit_ids,
        })
    }
}
