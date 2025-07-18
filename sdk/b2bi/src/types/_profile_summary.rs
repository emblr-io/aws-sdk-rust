// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the details for a profile. A profile is the mechanism used to create the concept of a private network.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProfileSummary {
    /// <p>Returns the unique, system-generated identifier for the profile.</p>
    pub profile_id: ::std::string::String,
    /// <p>Returns the display name for profile.</p>
    pub name: ::std::string::String,
    /// <p>Returns the name for the business associated with this profile.</p>
    pub business_name: ::std::string::String,
    /// <p>Specifies whether or not logging is enabled for this profile.</p>
    pub logging: ::std::option::Option<crate::types::Logging>,
    /// <p>Returns the name of the logging group.</p>
    pub log_group_name: ::std::option::Option<::std::string::String>,
    /// <p>Returns the timestamp for creation date and time of the profile.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>Returns the timestamp that identifies the most recent date and time that the profile was modified.</p>
    pub modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ProfileSummary {
    /// <p>Returns the unique, system-generated identifier for the profile.</p>
    pub fn profile_id(&self) -> &str {
        use std::ops::Deref;
        self.profile_id.deref()
    }
    /// <p>Returns the display name for profile.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>Returns the name for the business associated with this profile.</p>
    pub fn business_name(&self) -> &str {
        use std::ops::Deref;
        self.business_name.deref()
    }
    /// <p>Specifies whether or not logging is enabled for this profile.</p>
    pub fn logging(&self) -> ::std::option::Option<&crate::types::Logging> {
        self.logging.as_ref()
    }
    /// <p>Returns the name of the logging group.</p>
    pub fn log_group_name(&self) -> ::std::option::Option<&str> {
        self.log_group_name.as_deref()
    }
    /// <p>Returns the timestamp for creation date and time of the profile.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>Returns the timestamp that identifies the most recent date and time that the profile was modified.</p>
    pub fn modified_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.modified_at.as_ref()
    }
}
impl ProfileSummary {
    /// Creates a new builder-style object to manufacture [`ProfileSummary`](crate::types::ProfileSummary).
    pub fn builder() -> crate::types::builders::ProfileSummaryBuilder {
        crate::types::builders::ProfileSummaryBuilder::default()
    }
}

/// A builder for [`ProfileSummary`](crate::types::ProfileSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProfileSummaryBuilder {
    pub(crate) profile_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) business_name: ::std::option::Option<::std::string::String>,
    pub(crate) logging: ::std::option::Option<crate::types::Logging>,
    pub(crate) log_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ProfileSummaryBuilder {
    /// <p>Returns the unique, system-generated identifier for the profile.</p>
    /// This field is required.
    pub fn profile_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profile_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the unique, system-generated identifier for the profile.</p>
    pub fn set_profile_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profile_id = input;
        self
    }
    /// <p>Returns the unique, system-generated identifier for the profile.</p>
    pub fn get_profile_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.profile_id
    }
    /// <p>Returns the display name for profile.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the display name for profile.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Returns the display name for profile.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Returns the name for the business associated with this profile.</p>
    /// This field is required.
    pub fn business_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.business_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the name for the business associated with this profile.</p>
    pub fn set_business_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.business_name = input;
        self
    }
    /// <p>Returns the name for the business associated with this profile.</p>
    pub fn get_business_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.business_name
    }
    /// <p>Specifies whether or not logging is enabled for this profile.</p>
    pub fn logging(mut self, input: crate::types::Logging) -> Self {
        self.logging = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether or not logging is enabled for this profile.</p>
    pub fn set_logging(mut self, input: ::std::option::Option<crate::types::Logging>) -> Self {
        self.logging = input;
        self
    }
    /// <p>Specifies whether or not logging is enabled for this profile.</p>
    pub fn get_logging(&self) -> &::std::option::Option<crate::types::Logging> {
        &self.logging
    }
    /// <p>Returns the name of the logging group.</p>
    pub fn log_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns the name of the logging group.</p>
    pub fn set_log_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_name = input;
        self
    }
    /// <p>Returns the name of the logging group.</p>
    pub fn get_log_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_name
    }
    /// <p>Returns the timestamp for creation date and time of the profile.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns the timestamp for creation date and time of the profile.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>Returns the timestamp for creation date and time of the profile.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>Returns the timestamp that identifies the most recent date and time that the profile was modified.</p>
    pub fn modified_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.modified_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns the timestamp that identifies the most recent date and time that the profile was modified.</p>
    pub fn set_modified_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.modified_at = input;
        self
    }
    /// <p>Returns the timestamp that identifies the most recent date and time that the profile was modified.</p>
    pub fn get_modified_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.modified_at
    }
    /// Consumes the builder and constructs a [`ProfileSummary`](crate::types::ProfileSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`profile_id`](crate::types::builders::ProfileSummaryBuilder::profile_id)
    /// - [`name`](crate::types::builders::ProfileSummaryBuilder::name)
    /// - [`business_name`](crate::types::builders::ProfileSummaryBuilder::business_name)
    /// - [`created_at`](crate::types::builders::ProfileSummaryBuilder::created_at)
    pub fn build(self) -> ::std::result::Result<crate::types::ProfileSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ProfileSummary {
            profile_id: self.profile_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "profile_id",
                    "profile_id was not specified but it is required when building ProfileSummary",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building ProfileSummary",
                )
            })?,
            business_name: self.business_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "business_name",
                    "business_name was not specified but it is required when building ProfileSummary",
                )
            })?,
            logging: self.logging,
            log_group_name: self.log_group_name,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building ProfileSummary",
                )
            })?,
            modified_at: self.modified_at,
        })
    }
}
