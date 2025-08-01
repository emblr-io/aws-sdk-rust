// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreatePushNotificationRegistrationOutput {
    /// <p>The identifier for the registration.</p>
    pub registration_id: ::std::string::String,
    _request_id: Option<String>,
}
impl CreatePushNotificationRegistrationOutput {
    /// <p>The identifier for the registration.</p>
    pub fn registration_id(&self) -> &str {
        use std::ops::Deref;
        self.registration_id.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreatePushNotificationRegistrationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreatePushNotificationRegistrationOutput {
    /// Creates a new builder-style object to manufacture [`CreatePushNotificationRegistrationOutput`](crate::operation::create_push_notification_registration::CreatePushNotificationRegistrationOutput).
    pub fn builder() -> crate::operation::create_push_notification_registration::builders::CreatePushNotificationRegistrationOutputBuilder {
        crate::operation::create_push_notification_registration::builders::CreatePushNotificationRegistrationOutputBuilder::default()
    }
}

/// A builder for [`CreatePushNotificationRegistrationOutput`](crate::operation::create_push_notification_registration::CreatePushNotificationRegistrationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreatePushNotificationRegistrationOutputBuilder {
    pub(crate) registration_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreatePushNotificationRegistrationOutputBuilder {
    /// <p>The identifier for the registration.</p>
    /// This field is required.
    pub fn registration_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registration_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the registration.</p>
    pub fn set_registration_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registration_id = input;
        self
    }
    /// <p>The identifier for the registration.</p>
    pub fn get_registration_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.registration_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreatePushNotificationRegistrationOutput`](crate::operation::create_push_notification_registration::CreatePushNotificationRegistrationOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`registration_id`](crate::operation::create_push_notification_registration::builders::CreatePushNotificationRegistrationOutputBuilder::registration_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_push_notification_registration::CreatePushNotificationRegistrationOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::create_push_notification_registration::CreatePushNotificationRegistrationOutput {
                registration_id: self.registration_id.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "registration_id",
                        "registration_id was not specified but it is required when building CreatePushNotificationRegistrationOutput",
                    )
                })?,
                _request_id: self._request_id,
            },
        )
    }
}
