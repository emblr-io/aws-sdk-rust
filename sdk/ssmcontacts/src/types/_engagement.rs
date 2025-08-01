// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Incident Manager reaching out to a contact or escalation plan to engage contact during an incident.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Engagement {
    /// <p>The Amazon Resource Name (ARN) of the engagement.</p>
    pub engagement_arn: ::std::string::String,
    /// <p>The ARN of the escalation plan or contact that Incident Manager is engaging.</p>
    pub contact_arn: ::std::string::String,
    /// <p>The user that started the engagement.</p>
    pub sender: ::std::string::String,
    /// <p>The ARN of the incident that's engaging the contact.</p>
    pub incident_id: ::std::option::Option<::std::string::String>,
    /// <p>The time that the engagement began.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time that the engagement ended.</p>
    pub stop_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl Engagement {
    /// <p>The Amazon Resource Name (ARN) of the engagement.</p>
    pub fn engagement_arn(&self) -> &str {
        use std::ops::Deref;
        self.engagement_arn.deref()
    }
    /// <p>The ARN of the escalation plan or contact that Incident Manager is engaging.</p>
    pub fn contact_arn(&self) -> &str {
        use std::ops::Deref;
        self.contact_arn.deref()
    }
    /// <p>The user that started the engagement.</p>
    pub fn sender(&self) -> &str {
        use std::ops::Deref;
        self.sender.deref()
    }
    /// <p>The ARN of the incident that's engaging the contact.</p>
    pub fn incident_id(&self) -> ::std::option::Option<&str> {
        self.incident_id.as_deref()
    }
    /// <p>The time that the engagement began.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The time that the engagement ended.</p>
    pub fn stop_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.stop_time.as_ref()
    }
}
impl Engagement {
    /// Creates a new builder-style object to manufacture [`Engagement`](crate::types::Engagement).
    pub fn builder() -> crate::types::builders::EngagementBuilder {
        crate::types::builders::EngagementBuilder::default()
    }
}

/// A builder for [`Engagement`](crate::types::Engagement).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EngagementBuilder {
    pub(crate) engagement_arn: ::std::option::Option<::std::string::String>,
    pub(crate) contact_arn: ::std::option::Option<::std::string::String>,
    pub(crate) sender: ::std::option::Option<::std::string::String>,
    pub(crate) incident_id: ::std::option::Option<::std::string::String>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) stop_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl EngagementBuilder {
    /// <p>The Amazon Resource Name (ARN) of the engagement.</p>
    /// This field is required.
    pub fn engagement_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engagement_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the engagement.</p>
    pub fn set_engagement_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engagement_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the engagement.</p>
    pub fn get_engagement_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.engagement_arn
    }
    /// <p>The ARN of the escalation plan or contact that Incident Manager is engaging.</p>
    /// This field is required.
    pub fn contact_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.contact_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the escalation plan or contact that Incident Manager is engaging.</p>
    pub fn set_contact_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.contact_arn = input;
        self
    }
    /// <p>The ARN of the escalation plan or contact that Incident Manager is engaging.</p>
    pub fn get_contact_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.contact_arn
    }
    /// <p>The user that started the engagement.</p>
    /// This field is required.
    pub fn sender(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sender = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user that started the engagement.</p>
    pub fn set_sender(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sender = input;
        self
    }
    /// <p>The user that started the engagement.</p>
    pub fn get_sender(&self) -> &::std::option::Option<::std::string::String> {
        &self.sender
    }
    /// <p>The ARN of the incident that's engaging the contact.</p>
    pub fn incident_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.incident_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the incident that's engaging the contact.</p>
    pub fn set_incident_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.incident_id = input;
        self
    }
    /// <p>The ARN of the incident that's engaging the contact.</p>
    pub fn get_incident_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.incident_id
    }
    /// <p>The time that the engagement began.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the engagement began.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The time that the engagement began.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The time that the engagement ended.</p>
    pub fn stop_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.stop_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the engagement ended.</p>
    pub fn set_stop_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.stop_time = input;
        self
    }
    /// <p>The time that the engagement ended.</p>
    pub fn get_stop_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.stop_time
    }
    /// Consumes the builder and constructs a [`Engagement`](crate::types::Engagement).
    /// This method will fail if any of the following fields are not set:
    /// - [`engagement_arn`](crate::types::builders::EngagementBuilder::engagement_arn)
    /// - [`contact_arn`](crate::types::builders::EngagementBuilder::contact_arn)
    /// - [`sender`](crate::types::builders::EngagementBuilder::sender)
    pub fn build(self) -> ::std::result::Result<crate::types::Engagement, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Engagement {
            engagement_arn: self.engagement_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "engagement_arn",
                    "engagement_arn was not specified but it is required when building Engagement",
                )
            })?,
            contact_arn: self.contact_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "contact_arn",
                    "contact_arn was not specified but it is required when building Engagement",
                )
            })?,
            sender: self.sender.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sender",
                    "sender was not specified but it is required when building Engagement",
                )
            })?,
            incident_id: self.incident_id,
            start_time: self.start_time,
            stop_time: self.stop_time,
        })
    }
}
