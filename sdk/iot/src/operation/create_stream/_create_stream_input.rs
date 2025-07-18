// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateStreamInput {
    /// <p>The stream ID.</p>
    pub stream_id: ::std::option::Option<::std::string::String>,
    /// <p>A description of the stream.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The files to stream.</p>
    pub files: ::std::option::Option<::std::vec::Vec<crate::types::StreamFile>>,
    /// <p>An IAM role that allows the IoT service principal to access your S3 files.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>Metadata which can be used to manage streams.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateStreamInput {
    /// <p>The stream ID.</p>
    pub fn stream_id(&self) -> ::std::option::Option<&str> {
        self.stream_id.as_deref()
    }
    /// <p>A description of the stream.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The files to stream.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.files.is_none()`.
    pub fn files(&self) -> &[crate::types::StreamFile] {
        self.files.as_deref().unwrap_or_default()
    }
    /// <p>An IAM role that allows the IoT service principal to access your S3 files.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>Metadata which can be used to manage streams.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateStreamInput {
    /// Creates a new builder-style object to manufacture [`CreateStreamInput`](crate::operation::create_stream::CreateStreamInput).
    pub fn builder() -> crate::operation::create_stream::builders::CreateStreamInputBuilder {
        crate::operation::create_stream::builders::CreateStreamInputBuilder::default()
    }
}

/// A builder for [`CreateStreamInput`](crate::operation::create_stream::CreateStreamInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateStreamInputBuilder {
    pub(crate) stream_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) files: ::std::option::Option<::std::vec::Vec<crate::types::StreamFile>>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateStreamInputBuilder {
    /// <p>The stream ID.</p>
    /// This field is required.
    pub fn stream_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The stream ID.</p>
    pub fn set_stream_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_id = input;
        self
    }
    /// <p>The stream ID.</p>
    pub fn get_stream_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_id
    }
    /// <p>A description of the stream.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the stream.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the stream.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `files`.
    ///
    /// To override the contents of this collection use [`set_files`](Self::set_files).
    ///
    /// <p>The files to stream.</p>
    pub fn files(mut self, input: crate::types::StreamFile) -> Self {
        let mut v = self.files.unwrap_or_default();
        v.push(input);
        self.files = ::std::option::Option::Some(v);
        self
    }
    /// <p>The files to stream.</p>
    pub fn set_files(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StreamFile>>) -> Self {
        self.files = input;
        self
    }
    /// <p>The files to stream.</p>
    pub fn get_files(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StreamFile>> {
        &self.files
    }
    /// <p>An IAM role that allows the IoT service principal to access your S3 files.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An IAM role that allows the IoT service principal to access your S3 files.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>An IAM role that allows the IoT service principal to access your S3 files.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Metadata which can be used to manage streams.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Metadata which can be used to manage streams.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Metadata which can be used to manage streams.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateStreamInput`](crate::operation::create_stream::CreateStreamInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_stream::CreateStreamInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_stream::CreateStreamInput {
            stream_id: self.stream_id,
            description: self.description,
            files: self.files,
            role_arn: self.role_arn,
            tags: self.tags,
        })
    }
}
