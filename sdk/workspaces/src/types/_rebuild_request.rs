// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the information used to rebuild a WorkSpace.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RebuildRequest {
    /// <p>The identifier of the WorkSpace.</p>
    pub workspace_id: ::std::string::String,
}
impl RebuildRequest {
    /// <p>The identifier of the WorkSpace.</p>
    pub fn workspace_id(&self) -> &str {
        use std::ops::Deref;
        self.workspace_id.deref()
    }
}
impl RebuildRequest {
    /// Creates a new builder-style object to manufacture [`RebuildRequest`](crate::types::RebuildRequest).
    pub fn builder() -> crate::types::builders::RebuildRequestBuilder {
        crate::types::builders::RebuildRequestBuilder::default()
    }
}

/// A builder for [`RebuildRequest`](crate::types::RebuildRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RebuildRequestBuilder {
    pub(crate) workspace_id: ::std::option::Option<::std::string::String>,
}
impl RebuildRequestBuilder {
    /// <p>The identifier of the WorkSpace.</p>
    /// This field is required.
    pub fn workspace_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workspace_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the WorkSpace.</p>
    pub fn set_workspace_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workspace_id = input;
        self
    }
    /// <p>The identifier of the WorkSpace.</p>
    pub fn get_workspace_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workspace_id
    }
    /// Consumes the builder and constructs a [`RebuildRequest`](crate::types::RebuildRequest).
    /// This method will fail if any of the following fields are not set:
    /// - [`workspace_id`](crate::types::builders::RebuildRequestBuilder::workspace_id)
    pub fn build(self) -> ::std::result::Result<crate::types::RebuildRequest, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RebuildRequest {
            workspace_id: self.workspace_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "workspace_id",
                    "workspace_id was not specified but it is required when building RebuildRequest",
                )
            })?,
        })
    }
}
