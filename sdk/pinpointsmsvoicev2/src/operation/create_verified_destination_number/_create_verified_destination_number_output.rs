// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateVerifiedDestinationNumberOutput {
    /// <p>The Amazon Resource Name (ARN) for the verified destination phone number.</p>
    pub verified_destination_number_arn: ::std::string::String,
    /// <p>The unique identifier for the verified destination phone number.</p>
    pub verified_destination_number_id: ::std::string::String,
    /// <p>The verified destination phone number, in E.164 format.</p>
    pub destination_phone_number: ::std::string::String,
    /// <p>The status of the verified destination phone number.</p>
    /// <ul>
    /// <li>
    /// <p><code>PENDING</code>: The phone number hasn't been verified yet.</p></li>
    /// <li>
    /// <p><code>VERIFIED</code>: The phone number is verified and can receive messages.</p></li>
    /// </ul>
    pub status: crate::types::VerificationStatus,
    /// <p>An array of tags (key and value pairs) to associate with the destination number.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The time when the verified phone number was created, in <a href="https://www.epochconverter.com/">UNIX epoch time</a> format.</p>
    pub created_timestamp: ::aws_smithy_types::DateTime,
    _request_id: Option<String>,
}
impl CreateVerifiedDestinationNumberOutput {
    /// <p>The Amazon Resource Name (ARN) for the verified destination phone number.</p>
    pub fn verified_destination_number_arn(&self) -> &str {
        use std::ops::Deref;
        self.verified_destination_number_arn.deref()
    }
    /// <p>The unique identifier for the verified destination phone number.</p>
    pub fn verified_destination_number_id(&self) -> &str {
        use std::ops::Deref;
        self.verified_destination_number_id.deref()
    }
    /// <p>The verified destination phone number, in E.164 format.</p>
    pub fn destination_phone_number(&self) -> &str {
        use std::ops::Deref;
        self.destination_phone_number.deref()
    }
    /// <p>The status of the verified destination phone number.</p>
    /// <ul>
    /// <li>
    /// <p><code>PENDING</code>: The phone number hasn't been verified yet.</p></li>
    /// <li>
    /// <p><code>VERIFIED</code>: The phone number is verified and can receive messages.</p></li>
    /// </ul>
    pub fn status(&self) -> &crate::types::VerificationStatus {
        &self.status
    }
    /// <p>An array of tags (key and value pairs) to associate with the destination number.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The time when the verified phone number was created, in <a href="https://www.epochconverter.com/">UNIX epoch time</a> format.</p>
    pub fn created_timestamp(&self) -> &::aws_smithy_types::DateTime {
        &self.created_timestamp
    }
}
impl ::aws_types::request_id::RequestId for CreateVerifiedDestinationNumberOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateVerifiedDestinationNumberOutput {
    /// Creates a new builder-style object to manufacture [`CreateVerifiedDestinationNumberOutput`](crate::operation::create_verified_destination_number::CreateVerifiedDestinationNumberOutput).
    pub fn builder() -> crate::operation::create_verified_destination_number::builders::CreateVerifiedDestinationNumberOutputBuilder {
        crate::operation::create_verified_destination_number::builders::CreateVerifiedDestinationNumberOutputBuilder::default()
    }
}

/// A builder for [`CreateVerifiedDestinationNumberOutput`](crate::operation::create_verified_destination_number::CreateVerifiedDestinationNumberOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateVerifiedDestinationNumberOutputBuilder {
    pub(crate) verified_destination_number_arn: ::std::option::Option<::std::string::String>,
    pub(crate) verified_destination_number_id: ::std::option::Option<::std::string::String>,
    pub(crate) destination_phone_number: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::VerificationStatus>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl CreateVerifiedDestinationNumberOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) for the verified destination phone number.</p>
    /// This field is required.
    pub fn verified_destination_number_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.verified_destination_number_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the verified destination phone number.</p>
    pub fn set_verified_destination_number_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.verified_destination_number_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the verified destination phone number.</p>
    pub fn get_verified_destination_number_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.verified_destination_number_arn
    }
    /// <p>The unique identifier for the verified destination phone number.</p>
    /// This field is required.
    pub fn verified_destination_number_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.verified_destination_number_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the verified destination phone number.</p>
    pub fn set_verified_destination_number_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.verified_destination_number_id = input;
        self
    }
    /// <p>The unique identifier for the verified destination phone number.</p>
    pub fn get_verified_destination_number_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.verified_destination_number_id
    }
    /// <p>The verified destination phone number, in E.164 format.</p>
    /// This field is required.
    pub fn destination_phone_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_phone_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The verified destination phone number, in E.164 format.</p>
    pub fn set_destination_phone_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_phone_number = input;
        self
    }
    /// <p>The verified destination phone number, in E.164 format.</p>
    pub fn get_destination_phone_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_phone_number
    }
    /// <p>The status of the verified destination phone number.</p>
    /// <ul>
    /// <li>
    /// <p><code>PENDING</code>: The phone number hasn't been verified yet.</p></li>
    /// <li>
    /// <p><code>VERIFIED</code>: The phone number is verified and can receive messages.</p></li>
    /// </ul>
    /// This field is required.
    pub fn status(mut self, input: crate::types::VerificationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the verified destination phone number.</p>
    /// <ul>
    /// <li>
    /// <p><code>PENDING</code>: The phone number hasn't been verified yet.</p></li>
    /// <li>
    /// <p><code>VERIFIED</code>: The phone number is verified and can receive messages.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::VerificationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the verified destination phone number.</p>
    /// <ul>
    /// <li>
    /// <p><code>PENDING</code>: The phone number hasn't been verified yet.</p></li>
    /// <li>
    /// <p><code>VERIFIED</code>: The phone number is verified and can receive messages.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::VerificationStatus> {
        &self.status
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>An array of tags (key and value pairs) to associate with the destination number.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of tags (key and value pairs) to associate with the destination number.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>An array of tags (key and value pairs) to associate with the destination number.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The time when the verified phone number was created, in <a href="https://www.epochconverter.com/">UNIX epoch time</a> format.</p>
    /// This field is required.
    pub fn created_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when the verified phone number was created, in <a href="https://www.epochconverter.com/">UNIX epoch time</a> format.</p>
    pub fn set_created_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_timestamp = input;
        self
    }
    /// <p>The time when the verified phone number was created, in <a href="https://www.epochconverter.com/">UNIX epoch time</a> format.</p>
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
    /// Consumes the builder and constructs a [`CreateVerifiedDestinationNumberOutput`](crate::operation::create_verified_destination_number::CreateVerifiedDestinationNumberOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`verified_destination_number_arn`](crate::operation::create_verified_destination_number::builders::CreateVerifiedDestinationNumberOutputBuilder::verified_destination_number_arn)
    /// - [`verified_destination_number_id`](crate::operation::create_verified_destination_number::builders::CreateVerifiedDestinationNumberOutputBuilder::verified_destination_number_id)
    /// - [`destination_phone_number`](crate::operation::create_verified_destination_number::builders::CreateVerifiedDestinationNumberOutputBuilder::destination_phone_number)
    /// - [`status`](crate::operation::create_verified_destination_number::builders::CreateVerifiedDestinationNumberOutputBuilder::status)
    /// - [`created_timestamp`](crate::operation::create_verified_destination_number::builders::CreateVerifiedDestinationNumberOutputBuilder::created_timestamp)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_verified_destination_number::CreateVerifiedDestinationNumberOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::create_verified_destination_number::CreateVerifiedDestinationNumberOutput {
                verified_destination_number_arn: self.verified_destination_number_arn.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "verified_destination_number_arn",
                        "verified_destination_number_arn was not specified but it is required when building CreateVerifiedDestinationNumberOutput",
                    )
                })?,
                verified_destination_number_id: self.verified_destination_number_id.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "verified_destination_number_id",
                        "verified_destination_number_id was not specified but it is required when building CreateVerifiedDestinationNumberOutput",
                    )
                })?,
                destination_phone_number: self.destination_phone_number.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "destination_phone_number",
                        "destination_phone_number was not specified but it is required when building CreateVerifiedDestinationNumberOutput",
                    )
                })?,
                status: self.status.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "status",
                        "status was not specified but it is required when building CreateVerifiedDestinationNumberOutput",
                    )
                })?,
                tags: self.tags,
                created_timestamp: self.created_timestamp.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "created_timestamp",
                        "created_timestamp was not specified but it is required when building CreateVerifiedDestinationNumberOutput",
                    )
                })?,
                _request_id: self._request_id,
            },
        )
    }
}
