// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteRegistrationAttachmentOutput {
    /// <p>The Amazon Resource Name (ARN) for the registration attachment.</p>
    pub registration_attachment_arn: ::std::string::String,
    /// <p>The unique identifier for the registration attachment.</p>
    pub registration_attachment_id: ::std::string::String,
    /// <p>The status of the registration attachment.</p>
    /// <ul>
    /// <li>
    /// <p><code>UPLOAD_IN_PROGRESS</code> The attachment is being uploaded.</p></li>
    /// <li>
    /// <p><code>UPLOAD_COMPLETE</code> The attachment has been uploaded.</p></li>
    /// <li>
    /// <p><code>UPLOAD_FAILED</code> The attachment failed to uploaded.</p></li>
    /// <li>
    /// <p><code>DELETED</code> The attachment has been deleted..</p></li>
    /// </ul>
    pub attachment_status: crate::types::AttachmentStatus,
    /// <p>The error message if the upload failed.</p>
    pub attachment_upload_error_reason: ::std::option::Option<crate::types::AttachmentUploadErrorReason>,
    /// <p>The time when the registration attachment was created, in <a href="https://www.epochconverter.com/">UNIX epoch time</a> format.</p>
    pub created_timestamp: ::aws_smithy_types::DateTime,
    _request_id: Option<String>,
}
impl DeleteRegistrationAttachmentOutput {
    /// <p>The Amazon Resource Name (ARN) for the registration attachment.</p>
    pub fn registration_attachment_arn(&self) -> &str {
        use std::ops::Deref;
        self.registration_attachment_arn.deref()
    }
    /// <p>The unique identifier for the registration attachment.</p>
    pub fn registration_attachment_id(&self) -> &str {
        use std::ops::Deref;
        self.registration_attachment_id.deref()
    }
    /// <p>The status of the registration attachment.</p>
    /// <ul>
    /// <li>
    /// <p><code>UPLOAD_IN_PROGRESS</code> The attachment is being uploaded.</p></li>
    /// <li>
    /// <p><code>UPLOAD_COMPLETE</code> The attachment has been uploaded.</p></li>
    /// <li>
    /// <p><code>UPLOAD_FAILED</code> The attachment failed to uploaded.</p></li>
    /// <li>
    /// <p><code>DELETED</code> The attachment has been deleted..</p></li>
    /// </ul>
    pub fn attachment_status(&self) -> &crate::types::AttachmentStatus {
        &self.attachment_status
    }
    /// <p>The error message if the upload failed.</p>
    pub fn attachment_upload_error_reason(&self) -> ::std::option::Option<&crate::types::AttachmentUploadErrorReason> {
        self.attachment_upload_error_reason.as_ref()
    }
    /// <p>The time when the registration attachment was created, in <a href="https://www.epochconverter.com/">UNIX epoch time</a> format.</p>
    pub fn created_timestamp(&self) -> &::aws_smithy_types::DateTime {
        &self.created_timestamp
    }
}
impl ::aws_types::request_id::RequestId for DeleteRegistrationAttachmentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteRegistrationAttachmentOutput {
    /// Creates a new builder-style object to manufacture [`DeleteRegistrationAttachmentOutput`](crate::operation::delete_registration_attachment::DeleteRegistrationAttachmentOutput).
    pub fn builder() -> crate::operation::delete_registration_attachment::builders::DeleteRegistrationAttachmentOutputBuilder {
        crate::operation::delete_registration_attachment::builders::DeleteRegistrationAttachmentOutputBuilder::default()
    }
}

/// A builder for [`DeleteRegistrationAttachmentOutput`](crate::operation::delete_registration_attachment::DeleteRegistrationAttachmentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteRegistrationAttachmentOutputBuilder {
    pub(crate) registration_attachment_arn: ::std::option::Option<::std::string::String>,
    pub(crate) registration_attachment_id: ::std::option::Option<::std::string::String>,
    pub(crate) attachment_status: ::std::option::Option<crate::types::AttachmentStatus>,
    pub(crate) attachment_upload_error_reason: ::std::option::Option<crate::types::AttachmentUploadErrorReason>,
    pub(crate) created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DeleteRegistrationAttachmentOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) for the registration attachment.</p>
    /// This field is required.
    pub fn registration_attachment_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registration_attachment_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the registration attachment.</p>
    pub fn set_registration_attachment_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registration_attachment_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the registration attachment.</p>
    pub fn get_registration_attachment_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.registration_attachment_arn
    }
    /// <p>The unique identifier for the registration attachment.</p>
    /// This field is required.
    pub fn registration_attachment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registration_attachment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the registration attachment.</p>
    pub fn set_registration_attachment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registration_attachment_id = input;
        self
    }
    /// <p>The unique identifier for the registration attachment.</p>
    pub fn get_registration_attachment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.registration_attachment_id
    }
    /// <p>The status of the registration attachment.</p>
    /// <ul>
    /// <li>
    /// <p><code>UPLOAD_IN_PROGRESS</code> The attachment is being uploaded.</p></li>
    /// <li>
    /// <p><code>UPLOAD_COMPLETE</code> The attachment has been uploaded.</p></li>
    /// <li>
    /// <p><code>UPLOAD_FAILED</code> The attachment failed to uploaded.</p></li>
    /// <li>
    /// <p><code>DELETED</code> The attachment has been deleted..</p></li>
    /// </ul>
    /// This field is required.
    pub fn attachment_status(mut self, input: crate::types::AttachmentStatus) -> Self {
        self.attachment_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the registration attachment.</p>
    /// <ul>
    /// <li>
    /// <p><code>UPLOAD_IN_PROGRESS</code> The attachment is being uploaded.</p></li>
    /// <li>
    /// <p><code>UPLOAD_COMPLETE</code> The attachment has been uploaded.</p></li>
    /// <li>
    /// <p><code>UPLOAD_FAILED</code> The attachment failed to uploaded.</p></li>
    /// <li>
    /// <p><code>DELETED</code> The attachment has been deleted..</p></li>
    /// </ul>
    pub fn set_attachment_status(mut self, input: ::std::option::Option<crate::types::AttachmentStatus>) -> Self {
        self.attachment_status = input;
        self
    }
    /// <p>The status of the registration attachment.</p>
    /// <ul>
    /// <li>
    /// <p><code>UPLOAD_IN_PROGRESS</code> The attachment is being uploaded.</p></li>
    /// <li>
    /// <p><code>UPLOAD_COMPLETE</code> The attachment has been uploaded.</p></li>
    /// <li>
    /// <p><code>UPLOAD_FAILED</code> The attachment failed to uploaded.</p></li>
    /// <li>
    /// <p><code>DELETED</code> The attachment has been deleted..</p></li>
    /// </ul>
    pub fn get_attachment_status(&self) -> &::std::option::Option<crate::types::AttachmentStatus> {
        &self.attachment_status
    }
    /// <p>The error message if the upload failed.</p>
    pub fn attachment_upload_error_reason(mut self, input: crate::types::AttachmentUploadErrorReason) -> Self {
        self.attachment_upload_error_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The error message if the upload failed.</p>
    pub fn set_attachment_upload_error_reason(mut self, input: ::std::option::Option<crate::types::AttachmentUploadErrorReason>) -> Self {
        self.attachment_upload_error_reason = input;
        self
    }
    /// <p>The error message if the upload failed.</p>
    pub fn get_attachment_upload_error_reason(&self) -> &::std::option::Option<crate::types::AttachmentUploadErrorReason> {
        &self.attachment_upload_error_reason
    }
    /// <p>The time when the registration attachment was created, in <a href="https://www.epochconverter.com/">UNIX epoch time</a> format.</p>
    /// This field is required.
    pub fn created_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when the registration attachment was created, in <a href="https://www.epochconverter.com/">UNIX epoch time</a> format.</p>
    pub fn set_created_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_timestamp = input;
        self
    }
    /// <p>The time when the registration attachment was created, in <a href="https://www.epochconverter.com/">UNIX epoch time</a> format.</p>
    pub fn get_created_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_timestamp
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteRegistrationAttachmentOutput`](crate::operation::delete_registration_attachment::DeleteRegistrationAttachmentOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`registration_attachment_arn`](crate::operation::delete_registration_attachment::builders::DeleteRegistrationAttachmentOutputBuilder::registration_attachment_arn)
    /// - [`registration_attachment_id`](crate::operation::delete_registration_attachment::builders::DeleteRegistrationAttachmentOutputBuilder::registration_attachment_id)
    /// - [`attachment_status`](crate::operation::delete_registration_attachment::builders::DeleteRegistrationAttachmentOutputBuilder::attachment_status)
    /// - [`created_timestamp`](crate::operation::delete_registration_attachment::builders::DeleteRegistrationAttachmentOutputBuilder::created_timestamp)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_registration_attachment::DeleteRegistrationAttachmentOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_registration_attachment::DeleteRegistrationAttachmentOutput {
            registration_attachment_arn: self.registration_attachment_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "registration_attachment_arn",
                    "registration_attachment_arn was not specified but it is required when building DeleteRegistrationAttachmentOutput",
                )
            })?,
            registration_attachment_id: self.registration_attachment_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "registration_attachment_id",
                    "registration_attachment_id was not specified but it is required when building DeleteRegistrationAttachmentOutput",
                )
            })?,
            attachment_status: self.attachment_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "attachment_status",
                    "attachment_status was not specified but it is required when building DeleteRegistrationAttachmentOutput",
                )
            })?,
            attachment_upload_error_reason: self.attachment_upload_error_reason,
            created_timestamp: self.created_timestamp.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_timestamp",
                    "created_timestamp was not specified but it is required when building DeleteRegistrationAttachmentOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
