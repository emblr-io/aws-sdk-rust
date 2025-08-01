// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the request to update the device status.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateDeviceStatusInput {
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    pub access_token: ::std::option::Option<::std::string::String>,
    /// <p>The device key of the device you want to update, for example <code>us-west-2_a1b2c3d4-5678-90ab-cdef-EXAMPLE11111</code>.</p>
    pub device_key: ::std::option::Option<::std::string::String>,
    /// <p>To enable device authentication with the specified device, set to <code>remembered</code>.To disable, set to <code>not_remembered</code>.</p>
    pub device_remembered_status: ::std::option::Option<crate::types::DeviceRememberedStatusType>,
}
impl UpdateDeviceStatusInput {
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    pub fn access_token(&self) -> ::std::option::Option<&str> {
        self.access_token.as_deref()
    }
    /// <p>The device key of the device you want to update, for example <code>us-west-2_a1b2c3d4-5678-90ab-cdef-EXAMPLE11111</code>.</p>
    pub fn device_key(&self) -> ::std::option::Option<&str> {
        self.device_key.as_deref()
    }
    /// <p>To enable device authentication with the specified device, set to <code>remembered</code>.To disable, set to <code>not_remembered</code>.</p>
    pub fn device_remembered_status(&self) -> ::std::option::Option<&crate::types::DeviceRememberedStatusType> {
        self.device_remembered_status.as_ref()
    }
}
impl ::std::fmt::Debug for UpdateDeviceStatusInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateDeviceStatusInput");
        formatter.field("access_token", &"*** Sensitive Data Redacted ***");
        formatter.field("device_key", &self.device_key);
        formatter.field("device_remembered_status", &self.device_remembered_status);
        formatter.finish()
    }
}
impl UpdateDeviceStatusInput {
    /// Creates a new builder-style object to manufacture [`UpdateDeviceStatusInput`](crate::operation::update_device_status::UpdateDeviceStatusInput).
    pub fn builder() -> crate::operation::update_device_status::builders::UpdateDeviceStatusInputBuilder {
        crate::operation::update_device_status::builders::UpdateDeviceStatusInputBuilder::default()
    }
}

/// A builder for [`UpdateDeviceStatusInput`](crate::operation::update_device_status::UpdateDeviceStatusInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateDeviceStatusInputBuilder {
    pub(crate) access_token: ::std::option::Option<::std::string::String>,
    pub(crate) device_key: ::std::option::Option<::std::string::String>,
    pub(crate) device_remembered_status: ::std::option::Option<crate::types::DeviceRememberedStatusType>,
}
impl UpdateDeviceStatusInputBuilder {
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    /// This field is required.
    pub fn access_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    pub fn set_access_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_token = input;
        self
    }
    /// <p>A valid access token that Amazon Cognito issued to the currently signed-in user. Must include a scope claim for <code>aws.cognito.signin.user.admin</code>.</p>
    pub fn get_access_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_token
    }
    /// <p>The device key of the device you want to update, for example <code>us-west-2_a1b2c3d4-5678-90ab-cdef-EXAMPLE11111</code>.</p>
    /// This field is required.
    pub fn device_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The device key of the device you want to update, for example <code>us-west-2_a1b2c3d4-5678-90ab-cdef-EXAMPLE11111</code>.</p>
    pub fn set_device_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device_key = input;
        self
    }
    /// <p>The device key of the device you want to update, for example <code>us-west-2_a1b2c3d4-5678-90ab-cdef-EXAMPLE11111</code>.</p>
    pub fn get_device_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.device_key
    }
    /// <p>To enable device authentication with the specified device, set to <code>remembered</code>.To disable, set to <code>not_remembered</code>.</p>
    pub fn device_remembered_status(mut self, input: crate::types::DeviceRememberedStatusType) -> Self {
        self.device_remembered_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>To enable device authentication with the specified device, set to <code>remembered</code>.To disable, set to <code>not_remembered</code>.</p>
    pub fn set_device_remembered_status(mut self, input: ::std::option::Option<crate::types::DeviceRememberedStatusType>) -> Self {
        self.device_remembered_status = input;
        self
    }
    /// <p>To enable device authentication with the specified device, set to <code>remembered</code>.To disable, set to <code>not_remembered</code>.</p>
    pub fn get_device_remembered_status(&self) -> &::std::option::Option<crate::types::DeviceRememberedStatusType> {
        &self.device_remembered_status
    }
    /// Consumes the builder and constructs a [`UpdateDeviceStatusInput`](crate::operation::update_device_status::UpdateDeviceStatusInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_device_status::UpdateDeviceStatusInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_device_status::UpdateDeviceStatusInput {
            access_token: self.access_token,
            device_key: self.device_key,
            device_remembered_status: self.device_remembered_status,
        })
    }
}
impl ::std::fmt::Debug for UpdateDeviceStatusInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateDeviceStatusInputBuilder");
        formatter.field("access_token", &"*** Sensitive Data Redacted ***");
        formatter.field("device_key", &self.device_key);
        formatter.field("device_remembered_status", &self.device_remembered_status);
        formatter.finish()
    }
}
