// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a virtual MFA device.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct VirtualMfaDevice {
    /// <p>The serial number associated with <code>VirtualMFADevice</code>.</p>
    pub serial_number: ::std::string::String,
    /// <p>The base32 seed defined as specified in <a href="https://tools.ietf.org/html/rfc3548.txt">RFC3548</a>. The <code>Base32StringSeed</code> is base32-encoded.</p>
    pub base32_string_seed: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>A QR code PNG image that encodes <code>otpauth://totp/$virtualMFADeviceName@$AccountName?secret=$Base32String</code> where <code>$virtualMFADeviceName</code> is one of the create call arguments. <code>AccountName</code> is the user name if set (otherwise, the account ID otherwise), and <code>Base32String</code> is the seed in base32 format. The <code>Base32String</code> value is base64-encoded.</p>
    pub qr_code_png: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>The IAM user associated with this virtual MFA device.</p>
    pub user: ::std::option::Option<crate::types::User>,
    /// <p>The date and time on which the virtual MFA device was enabled.</p>
    pub enable_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A list of tags that are attached to the virtual MFA device. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl VirtualMfaDevice {
    /// <p>The serial number associated with <code>VirtualMFADevice</code>.</p>
    pub fn serial_number(&self) -> &str {
        use std::ops::Deref;
        self.serial_number.deref()
    }
    /// <p>The base32 seed defined as specified in <a href="https://tools.ietf.org/html/rfc3548.txt">RFC3548</a>. The <code>Base32StringSeed</code> is base32-encoded.</p>
    pub fn base32_string_seed(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.base32_string_seed.as_ref()
    }
    /// <p>A QR code PNG image that encodes <code>otpauth://totp/$virtualMFADeviceName@$AccountName?secret=$Base32String</code> where <code>$virtualMFADeviceName</code> is one of the create call arguments. <code>AccountName</code> is the user name if set (otherwise, the account ID otherwise), and <code>Base32String</code> is the seed in base32 format. The <code>Base32String</code> value is base64-encoded.</p>
    pub fn qr_code_png(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.qr_code_png.as_ref()
    }
    /// <p>The IAM user associated with this virtual MFA device.</p>
    pub fn user(&self) -> ::std::option::Option<&crate::types::User> {
        self.user.as_ref()
    }
    /// <p>The date and time on which the virtual MFA device was enabled.</p>
    pub fn enable_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.enable_date.as_ref()
    }
    /// <p>A list of tags that are attached to the virtual MFA device. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for VirtualMfaDevice {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("VirtualMfaDevice");
        formatter.field("serial_number", &self.serial_number);
        formatter.field("base32_string_seed", &"*** Sensitive Data Redacted ***");
        formatter.field("qr_code_png", &"*** Sensitive Data Redacted ***");
        formatter.field("user", &self.user);
        formatter.field("enable_date", &self.enable_date);
        formatter.field("tags", &self.tags);
        formatter.finish()
    }
}
impl VirtualMfaDevice {
    /// Creates a new builder-style object to manufacture [`VirtualMfaDevice`](crate::types::VirtualMfaDevice).
    pub fn builder() -> crate::types::builders::VirtualMfaDeviceBuilder {
        crate::types::builders::VirtualMfaDeviceBuilder::default()
    }
}

/// A builder for [`VirtualMfaDevice`](crate::types::VirtualMfaDevice).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct VirtualMfaDeviceBuilder {
    pub(crate) serial_number: ::std::option::Option<::std::string::String>,
    pub(crate) base32_string_seed: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) qr_code_png: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) user: ::std::option::Option<crate::types::User>,
    pub(crate) enable_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl VirtualMfaDeviceBuilder {
    /// <p>The serial number associated with <code>VirtualMFADevice</code>.</p>
    /// This field is required.
    pub fn serial_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.serial_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The serial number associated with <code>VirtualMFADevice</code>.</p>
    pub fn set_serial_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.serial_number = input;
        self
    }
    /// <p>The serial number associated with <code>VirtualMFADevice</code>.</p>
    pub fn get_serial_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.serial_number
    }
    /// <p>The base32 seed defined as specified in <a href="https://tools.ietf.org/html/rfc3548.txt">RFC3548</a>. The <code>Base32StringSeed</code> is base32-encoded.</p>
    pub fn base32_string_seed(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.base32_string_seed = ::std::option::Option::Some(input);
        self
    }
    /// <p>The base32 seed defined as specified in <a href="https://tools.ietf.org/html/rfc3548.txt">RFC3548</a>. The <code>Base32StringSeed</code> is base32-encoded.</p>
    pub fn set_base32_string_seed(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.base32_string_seed = input;
        self
    }
    /// <p>The base32 seed defined as specified in <a href="https://tools.ietf.org/html/rfc3548.txt">RFC3548</a>. The <code>Base32StringSeed</code> is base32-encoded.</p>
    pub fn get_base32_string_seed(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.base32_string_seed
    }
    /// <p>A QR code PNG image that encodes <code>otpauth://totp/$virtualMFADeviceName@$AccountName?secret=$Base32String</code> where <code>$virtualMFADeviceName</code> is one of the create call arguments. <code>AccountName</code> is the user name if set (otherwise, the account ID otherwise), and <code>Base32String</code> is the seed in base32 format. The <code>Base32String</code> value is base64-encoded.</p>
    pub fn qr_code_png(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.qr_code_png = ::std::option::Option::Some(input);
        self
    }
    /// <p>A QR code PNG image that encodes <code>otpauth://totp/$virtualMFADeviceName@$AccountName?secret=$Base32String</code> where <code>$virtualMFADeviceName</code> is one of the create call arguments. <code>AccountName</code> is the user name if set (otherwise, the account ID otherwise), and <code>Base32String</code> is the seed in base32 format. The <code>Base32String</code> value is base64-encoded.</p>
    pub fn set_qr_code_png(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.qr_code_png = input;
        self
    }
    /// <p>A QR code PNG image that encodes <code>otpauth://totp/$virtualMFADeviceName@$AccountName?secret=$Base32String</code> where <code>$virtualMFADeviceName</code> is one of the create call arguments. <code>AccountName</code> is the user name if set (otherwise, the account ID otherwise), and <code>Base32String</code> is the seed in base32 format. The <code>Base32String</code> value is base64-encoded.</p>
    pub fn get_qr_code_png(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.qr_code_png
    }
    /// <p>The IAM user associated with this virtual MFA device.</p>
    pub fn user(mut self, input: crate::types::User) -> Self {
        self.user = ::std::option::Option::Some(input);
        self
    }
    /// <p>The IAM user associated with this virtual MFA device.</p>
    pub fn set_user(mut self, input: ::std::option::Option<crate::types::User>) -> Self {
        self.user = input;
        self
    }
    /// <p>The IAM user associated with this virtual MFA device.</p>
    pub fn get_user(&self) -> &::std::option::Option<crate::types::User> {
        &self.user
    }
    /// <p>The date and time on which the virtual MFA device was enabled.</p>
    pub fn enable_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.enable_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time on which the virtual MFA device was enabled.</p>
    pub fn set_enable_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.enable_date = input;
        self
    }
    /// <p>The date and time on which the virtual MFA device was enabled.</p>
    pub fn get_enable_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.enable_date
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags that are attached to the virtual MFA device. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags that are attached to the virtual MFA device. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags that are attached to the virtual MFA device. For more information about tagging, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html">Tagging IAM resources</a> in the <i>IAM User Guide</i>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`VirtualMfaDevice`](crate::types::VirtualMfaDevice).
    /// This method will fail if any of the following fields are not set:
    /// - [`serial_number`](crate::types::builders::VirtualMfaDeviceBuilder::serial_number)
    pub fn build(self) -> ::std::result::Result<crate::types::VirtualMfaDevice, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VirtualMfaDevice {
            serial_number: self.serial_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "serial_number",
                    "serial_number was not specified but it is required when building VirtualMfaDevice",
                )
            })?,
            base32_string_seed: self.base32_string_seed,
            qr_code_png: self.qr_code_png,
            user: self.user,
            enable_date: self.enable_date,
            tags: self.tags,
        })
    }
}
impl ::std::fmt::Debug for VirtualMfaDeviceBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("VirtualMfaDeviceBuilder");
        formatter.field("serial_number", &self.serial_number);
        formatter.field("base32_string_seed", &"*** Sensitive Data Redacted ***");
        formatter.field("qr_code_png", &"*** Sensitive Data Redacted ***");
        formatter.field("user", &self.user);
        formatter.field("enable_date", &self.enable_date);
        formatter.field("tags", &self.tags);
        formatter.finish()
    }
}
