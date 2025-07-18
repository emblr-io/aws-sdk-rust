// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSegmentVersionInput {
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the segment.</p>
    pub segment_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique version number (Version property) for the campaign version.</p>
    pub version: ::std::option::Option<::std::string::String>,
}
impl GetSegmentVersionInput {
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The unique identifier for the segment.</p>
    pub fn segment_id(&self) -> ::std::option::Option<&str> {
        self.segment_id.as_deref()
    }
    /// <p>The unique version number (Version property) for the campaign version.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
}
impl GetSegmentVersionInput {
    /// Creates a new builder-style object to manufacture [`GetSegmentVersionInput`](crate::operation::get_segment_version::GetSegmentVersionInput).
    pub fn builder() -> crate::operation::get_segment_version::builders::GetSegmentVersionInputBuilder {
        crate::operation::get_segment_version::builders::GetSegmentVersionInputBuilder::default()
    }
}

/// A builder for [`GetSegmentVersionInput`](crate::operation::get_segment_version::GetSegmentVersionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSegmentVersionInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) segment_id: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
}
impl GetSegmentVersionInputBuilder {
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The unique identifier for the segment.</p>
    /// This field is required.
    pub fn segment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.segment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the segment.</p>
    pub fn set_segment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.segment_id = input;
        self
    }
    /// <p>The unique identifier for the segment.</p>
    pub fn get_segment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.segment_id
    }
    /// <p>The unique version number (Version property) for the campaign version.</p>
    /// This field is required.
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique version number (Version property) for the campaign version.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The unique version number (Version property) for the campaign version.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Consumes the builder and constructs a [`GetSegmentVersionInput`](crate::operation::get_segment_version::GetSegmentVersionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_segment_version::GetSegmentVersionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_segment_version::GetSegmentVersionInput {
            application_id: self.application_id,
            segment_id: self.segment_id,
            version: self.version,
        })
    }
}
