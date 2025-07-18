// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>SetSMBGuestPasswordInput</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct SetSmbGuestPasswordInput {
    /// <p>The Amazon Resource Name (ARN) of the S3 File Gateway the SMB file share is associated with.</p>
    pub gateway_arn: ::std::option::Option<::std::string::String>,
    /// <p>The password that you want to set for your SMB server.</p>
    pub password: ::std::option::Option<::std::string::String>,
}
impl SetSmbGuestPasswordInput {
    /// <p>The Amazon Resource Name (ARN) of the S3 File Gateway the SMB file share is associated with.</p>
    pub fn gateway_arn(&self) -> ::std::option::Option<&str> {
        self.gateway_arn.as_deref()
    }
    /// <p>The password that you want to set for your SMB server.</p>
    pub fn password(&self) -> ::std::option::Option<&str> {
        self.password.as_deref()
    }
}
impl ::std::fmt::Debug for SetSmbGuestPasswordInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SetSmbGuestPasswordInput");
        formatter.field("gateway_arn", &self.gateway_arn);
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl SetSmbGuestPasswordInput {
    /// Creates a new builder-style object to manufacture [`SetSmbGuestPasswordInput`](crate::operation::set_smb_guest_password::SetSmbGuestPasswordInput).
    pub fn builder() -> crate::operation::set_smb_guest_password::builders::SetSmbGuestPasswordInputBuilder {
        crate::operation::set_smb_guest_password::builders::SetSmbGuestPasswordInputBuilder::default()
    }
}

/// A builder for [`SetSmbGuestPasswordInput`](crate::operation::set_smb_guest_password::SetSmbGuestPasswordInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct SetSmbGuestPasswordInputBuilder {
    pub(crate) gateway_arn: ::std::option::Option<::std::string::String>,
    pub(crate) password: ::std::option::Option<::std::string::String>,
}
impl SetSmbGuestPasswordInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the S3 File Gateway the SMB file share is associated with.</p>
    /// This field is required.
    pub fn gateway_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the S3 File Gateway the SMB file share is associated with.</p>
    pub fn set_gateway_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the S3 File Gateway the SMB file share is associated with.</p>
    pub fn get_gateway_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_arn
    }
    /// <p>The password that you want to set for your SMB server.</p>
    /// This field is required.
    pub fn password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The password that you want to set for your SMB server.</p>
    pub fn set_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.password = input;
        self
    }
    /// <p>The password that you want to set for your SMB server.</p>
    pub fn get_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.password
    }
    /// Consumes the builder and constructs a [`SetSmbGuestPasswordInput`](crate::operation::set_smb_guest_password::SetSmbGuestPasswordInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::set_smb_guest_password::SetSmbGuestPasswordInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::set_smb_guest_password::SetSmbGuestPasswordInput {
            gateway_arn: self.gateway_arn,
            password: self.password,
        })
    }
}
impl ::std::fmt::Debug for SetSmbGuestPasswordInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SetSmbGuestPasswordInputBuilder");
        formatter.field("gateway_arn", &self.gateway_arn);
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
