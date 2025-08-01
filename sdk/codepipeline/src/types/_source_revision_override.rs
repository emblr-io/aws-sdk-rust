// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list that allows you to specify, or override, the source revision for a pipeline execution that's being started. A source revision is the version with all the changes to your application code, or source artifact, for the pipeline execution.</p><note>
/// <p>For the <code>S3_OBJECT_VERSION_ID</code> and <code>S3_OBJECT_KEY</code> types of source revisions, either of the types can be used independently, or they can be used together to override the source with a specific ObjectKey and VersionID.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SourceRevisionOverride {
    /// <p>The name of the action where the override will be applied.</p>
    pub action_name: ::std::string::String,
    /// <p>The type of source revision, based on the source provider. For example, the revision type for the CodeCommit action provider is the commit ID.</p>
    pub revision_type: crate::types::SourceRevisionType,
    /// <p>The source revision, or version of your source artifact, with the changes that you want to run in the pipeline execution.</p>
    pub revision_value: ::std::string::String,
}
impl SourceRevisionOverride {
    /// <p>The name of the action where the override will be applied.</p>
    pub fn action_name(&self) -> &str {
        use std::ops::Deref;
        self.action_name.deref()
    }
    /// <p>The type of source revision, based on the source provider. For example, the revision type for the CodeCommit action provider is the commit ID.</p>
    pub fn revision_type(&self) -> &crate::types::SourceRevisionType {
        &self.revision_type
    }
    /// <p>The source revision, or version of your source artifact, with the changes that you want to run in the pipeline execution.</p>
    pub fn revision_value(&self) -> &str {
        use std::ops::Deref;
        self.revision_value.deref()
    }
}
impl SourceRevisionOverride {
    /// Creates a new builder-style object to manufacture [`SourceRevisionOverride`](crate::types::SourceRevisionOverride).
    pub fn builder() -> crate::types::builders::SourceRevisionOverrideBuilder {
        crate::types::builders::SourceRevisionOverrideBuilder::default()
    }
}

/// A builder for [`SourceRevisionOverride`](crate::types::SourceRevisionOverride).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SourceRevisionOverrideBuilder {
    pub(crate) action_name: ::std::option::Option<::std::string::String>,
    pub(crate) revision_type: ::std::option::Option<crate::types::SourceRevisionType>,
    pub(crate) revision_value: ::std::option::Option<::std::string::String>,
}
impl SourceRevisionOverrideBuilder {
    /// <p>The name of the action where the override will be applied.</p>
    /// This field is required.
    pub fn action_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the action where the override will be applied.</p>
    pub fn set_action_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action_name = input;
        self
    }
    /// <p>The name of the action where the override will be applied.</p>
    pub fn get_action_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.action_name
    }
    /// <p>The type of source revision, based on the source provider. For example, the revision type for the CodeCommit action provider is the commit ID.</p>
    /// This field is required.
    pub fn revision_type(mut self, input: crate::types::SourceRevisionType) -> Self {
        self.revision_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of source revision, based on the source provider. For example, the revision type for the CodeCommit action provider is the commit ID.</p>
    pub fn set_revision_type(mut self, input: ::std::option::Option<crate::types::SourceRevisionType>) -> Self {
        self.revision_type = input;
        self
    }
    /// <p>The type of source revision, based on the source provider. For example, the revision type for the CodeCommit action provider is the commit ID.</p>
    pub fn get_revision_type(&self) -> &::std::option::Option<crate::types::SourceRevisionType> {
        &self.revision_type
    }
    /// <p>The source revision, or version of your source artifact, with the changes that you want to run in the pipeline execution.</p>
    /// This field is required.
    pub fn revision_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source revision, or version of your source artifact, with the changes that you want to run in the pipeline execution.</p>
    pub fn set_revision_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_value = input;
        self
    }
    /// <p>The source revision, or version of your source artifact, with the changes that you want to run in the pipeline execution.</p>
    pub fn get_revision_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_value
    }
    /// Consumes the builder and constructs a [`SourceRevisionOverride`](crate::types::SourceRevisionOverride).
    /// This method will fail if any of the following fields are not set:
    /// - [`action_name`](crate::types::builders::SourceRevisionOverrideBuilder::action_name)
    /// - [`revision_type`](crate::types::builders::SourceRevisionOverrideBuilder::revision_type)
    /// - [`revision_value`](crate::types::builders::SourceRevisionOverrideBuilder::revision_value)
    pub fn build(self) -> ::std::result::Result<crate::types::SourceRevisionOverride, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SourceRevisionOverride {
            action_name: self.action_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "action_name",
                    "action_name was not specified but it is required when building SourceRevisionOverride",
                )
            })?,
            revision_type: self.revision_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "revision_type",
                    "revision_type was not specified but it is required when building SourceRevisionOverride",
                )
            })?,
            revision_value: self.revision_value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "revision_value",
                    "revision_value was not specified but it is required when building SourceRevisionOverride",
                )
            })?,
        })
    }
}
