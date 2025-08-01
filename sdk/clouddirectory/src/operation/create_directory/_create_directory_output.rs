// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDirectoryOutput {
    /// <p>The ARN that is associated with the <code>Directory</code>. For more information, see <code>arns</code>.</p>
    pub directory_arn: ::std::string::String,
    /// <p>The name of the <code>Directory</code>.</p>
    pub name: ::std::string::String,
    /// <p>The root object node of the created directory.</p>
    pub object_identifier: ::std::string::String,
    /// <p>The ARN of the published schema in the <code>Directory</code>. Once a published schema is copied into the directory, it has its own ARN, which is referred to applied schema ARN. For more information, see <code>arns</code>.</p>
    pub applied_schema_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateDirectoryOutput {
    /// <p>The ARN that is associated with the <code>Directory</code>. For more information, see <code>arns</code>.</p>
    pub fn directory_arn(&self) -> &str {
        use std::ops::Deref;
        self.directory_arn.deref()
    }
    /// <p>The name of the <code>Directory</code>.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The root object node of the created directory.</p>
    pub fn object_identifier(&self) -> &str {
        use std::ops::Deref;
        self.object_identifier.deref()
    }
    /// <p>The ARN of the published schema in the <code>Directory</code>. Once a published schema is copied into the directory, it has its own ARN, which is referred to applied schema ARN. For more information, see <code>arns</code>.</p>
    pub fn applied_schema_arn(&self) -> &str {
        use std::ops::Deref;
        self.applied_schema_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateDirectoryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateDirectoryOutput {
    /// Creates a new builder-style object to manufacture [`CreateDirectoryOutput`](crate::operation::create_directory::CreateDirectoryOutput).
    pub fn builder() -> crate::operation::create_directory::builders::CreateDirectoryOutputBuilder {
        crate::operation::create_directory::builders::CreateDirectoryOutputBuilder::default()
    }
}

/// A builder for [`CreateDirectoryOutput`](crate::operation::create_directory::CreateDirectoryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDirectoryOutputBuilder {
    pub(crate) directory_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) object_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) applied_schema_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateDirectoryOutputBuilder {
    /// <p>The ARN that is associated with the <code>Directory</code>. For more information, see <code>arns</code>.</p>
    /// This field is required.
    pub fn directory_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN that is associated with the <code>Directory</code>. For more information, see <code>arns</code>.</p>
    pub fn set_directory_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_arn = input;
        self
    }
    /// <p>The ARN that is associated with the <code>Directory</code>. For more information, see <code>arns</code>.</p>
    pub fn get_directory_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_arn
    }
    /// <p>The name of the <code>Directory</code>.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the <code>Directory</code>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the <code>Directory</code>.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The root object node of the created directory.</p>
    /// This field is required.
    pub fn object_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.object_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The root object node of the created directory.</p>
    pub fn set_object_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.object_identifier = input;
        self
    }
    /// <p>The root object node of the created directory.</p>
    pub fn get_object_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.object_identifier
    }
    /// <p>The ARN of the published schema in the <code>Directory</code>. Once a published schema is copied into the directory, it has its own ARN, which is referred to applied schema ARN. For more information, see <code>arns</code>.</p>
    /// This field is required.
    pub fn applied_schema_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.applied_schema_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the published schema in the <code>Directory</code>. Once a published schema is copied into the directory, it has its own ARN, which is referred to applied schema ARN. For more information, see <code>arns</code>.</p>
    pub fn set_applied_schema_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.applied_schema_arn = input;
        self
    }
    /// <p>The ARN of the published schema in the <code>Directory</code>. Once a published schema is copied into the directory, it has its own ARN, which is referred to applied schema ARN. For more information, see <code>arns</code>.</p>
    pub fn get_applied_schema_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.applied_schema_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateDirectoryOutput`](crate::operation::create_directory::CreateDirectoryOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`directory_arn`](crate::operation::create_directory::builders::CreateDirectoryOutputBuilder::directory_arn)
    /// - [`name`](crate::operation::create_directory::builders::CreateDirectoryOutputBuilder::name)
    /// - [`object_identifier`](crate::operation::create_directory::builders::CreateDirectoryOutputBuilder::object_identifier)
    /// - [`applied_schema_arn`](crate::operation::create_directory::builders::CreateDirectoryOutputBuilder::applied_schema_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_directory::CreateDirectoryOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_directory::CreateDirectoryOutput {
            directory_arn: self.directory_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "directory_arn",
                    "directory_arn was not specified but it is required when building CreateDirectoryOutput",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building CreateDirectoryOutput",
                )
            })?,
            object_identifier: self.object_identifier.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "object_identifier",
                    "object_identifier was not specified but it is required when building CreateDirectoryOutput",
                )
            })?,
            applied_schema_arn: self.applied_schema_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "applied_schema_arn",
                    "applied_schema_arn was not specified but it is required when building CreateDirectoryOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
