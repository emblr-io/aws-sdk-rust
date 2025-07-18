// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSessionOutput {
    /// <p>The unique identifier for the session in UUID format.</p>
    pub session_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the session.</p>
    pub session_arn: ::std::string::String,
    /// <p>The current status of the session.</p>
    pub session_status: crate::types::SessionStatus,
    /// <p>The timestamp for when the session was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The timestamp for when the session was last modified.</p>
    pub last_updated_at: ::aws_smithy_types::DateTime,
    /// <p>A map of key-value pairs containing attributes persisted across the session.</p>
    pub session_metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service key used to encrypt the session data. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/session-encryption.html">Amazon Bedrock session encryption</a>.</p>
    pub encryption_key_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetSessionOutput {
    /// <p>The unique identifier for the session in UUID format.</p>
    pub fn session_id(&self) -> &str {
        use std::ops::Deref;
        self.session_id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the session.</p>
    pub fn session_arn(&self) -> &str {
        use std::ops::Deref;
        self.session_arn.deref()
    }
    /// <p>The current status of the session.</p>
    pub fn session_status(&self) -> &crate::types::SessionStatus {
        &self.session_status
    }
    /// <p>The timestamp for when the session was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The timestamp for when the session was last modified.</p>
    pub fn last_updated_at(&self) -> &::aws_smithy_types::DateTime {
        &self.last_updated_at
    }
    /// <p>A map of key-value pairs containing attributes persisted across the session.</p>
    pub fn session_metadata(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.session_metadata.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service key used to encrypt the session data. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/session-encryption.html">Amazon Bedrock session encryption</a>.</p>
    pub fn encryption_key_arn(&self) -> ::std::option::Option<&str> {
        self.encryption_key_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetSessionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSessionOutput {
    /// Creates a new builder-style object to manufacture [`GetSessionOutput`](crate::operation::get_session::GetSessionOutput).
    pub fn builder() -> crate::operation::get_session::builders::GetSessionOutputBuilder {
        crate::operation::get_session::builders::GetSessionOutputBuilder::default()
    }
}

/// A builder for [`GetSessionOutput`](crate::operation::get_session::GetSessionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSessionOutputBuilder {
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
    pub(crate) session_arn: ::std::option::Option<::std::string::String>,
    pub(crate) session_status: ::std::option::Option<crate::types::SessionStatus>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) session_metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) encryption_key_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetSessionOutputBuilder {
    /// <p>The unique identifier for the session in UUID format.</p>
    /// This field is required.
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the session in UUID format.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>The unique identifier for the session in UUID format.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    /// <p>The Amazon Resource Name (ARN) of the session.</p>
    /// This field is required.
    pub fn session_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the session.</p>
    pub fn set_session_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the session.</p>
    pub fn get_session_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_arn
    }
    /// <p>The current status of the session.</p>
    /// This field is required.
    pub fn session_status(mut self, input: crate::types::SessionStatus) -> Self {
        self.session_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the session.</p>
    pub fn set_session_status(mut self, input: ::std::option::Option<crate::types::SessionStatus>) -> Self {
        self.session_status = input;
        self
    }
    /// <p>The current status of the session.</p>
    pub fn get_session_status(&self) -> &::std::option::Option<crate::types::SessionStatus> {
        &self.session_status
    }
    /// <p>The timestamp for when the session was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the session was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp for when the session was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The timestamp for when the session was last modified.</p>
    /// This field is required.
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the session was last modified.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The timestamp for when the session was last modified.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// Adds a key-value pair to `session_metadata`.
    ///
    /// To override the contents of this collection use [`set_session_metadata`](Self::set_session_metadata).
    ///
    /// <p>A map of key-value pairs containing attributes persisted across the session.</p>
    pub fn session_metadata(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.session_metadata.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.session_metadata = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map of key-value pairs containing attributes persisted across the session.</p>
    pub fn set_session_metadata(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.session_metadata = input;
        self
    }
    /// <p>A map of key-value pairs containing attributes persisted across the session.</p>
    pub fn get_session_metadata(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.session_metadata
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service key used to encrypt the session data. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/session-encryption.html">Amazon Bedrock session encryption</a>.</p>
    pub fn encryption_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.encryption_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service key used to encrypt the session data. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/session-encryption.html">Amazon Bedrock session encryption</a>.</p>
    pub fn set_encryption_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.encryption_key_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service key used to encrypt the session data. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/session-encryption.html">Amazon Bedrock session encryption</a>.</p>
    pub fn get_encryption_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.encryption_key_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSessionOutput`](crate::operation::get_session::GetSessionOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`session_id`](crate::operation::get_session::builders::GetSessionOutputBuilder::session_id)
    /// - [`session_arn`](crate::operation::get_session::builders::GetSessionOutputBuilder::session_arn)
    /// - [`session_status`](crate::operation::get_session::builders::GetSessionOutputBuilder::session_status)
    /// - [`created_at`](crate::operation::get_session::builders::GetSessionOutputBuilder::created_at)
    /// - [`last_updated_at`](crate::operation::get_session::builders::GetSessionOutputBuilder::last_updated_at)
    pub fn build(self) -> ::std::result::Result<crate::operation::get_session::GetSessionOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_session::GetSessionOutput {
            session_id: self.session_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "session_id",
                    "session_id was not specified but it is required when building GetSessionOutput",
                )
            })?,
            session_arn: self.session_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "session_arn",
                    "session_arn was not specified but it is required when building GetSessionOutput",
                )
            })?,
            session_status: self.session_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "session_status",
                    "session_status was not specified but it is required when building GetSessionOutput",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building GetSessionOutput",
                )
            })?,
            last_updated_at: self.last_updated_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_updated_at",
                    "last_updated_at was not specified but it is required when building GetSessionOutput",
                )
            })?,
            session_metadata: self.session_metadata,
            encryption_key_arn: self.encryption_key_arn,
            _request_id: self._request_id,
        })
    }
}
