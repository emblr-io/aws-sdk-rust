// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Updates an existing documentation version of an API.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDocumentationVersionInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub rest_api_id: ::std::option::Option<::std::string::String>,
    /// <p>The version identifier of the to-be-updated documentation version.</p>
    pub documentation_version: ::std::option::Option<::std::string::String>,
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub patch_operations: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>,
}
impl UpdateDocumentationVersionInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn rest_api_id(&self) -> ::std::option::Option<&str> {
        self.rest_api_id.as_deref()
    }
    /// <p>The version identifier of the to-be-updated documentation version.</p>
    pub fn documentation_version(&self) -> ::std::option::Option<&str> {
        self.documentation_version.as_deref()
    }
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.patch_operations.is_none()`.
    pub fn patch_operations(&self) -> &[crate::types::PatchOperation] {
        self.patch_operations.as_deref().unwrap_or_default()
    }
}
impl UpdateDocumentationVersionInput {
    /// Creates a new builder-style object to manufacture [`UpdateDocumentationVersionInput`](crate::operation::update_documentation_version::UpdateDocumentationVersionInput).
    pub fn builder() -> crate::operation::update_documentation_version::builders::UpdateDocumentationVersionInputBuilder {
        crate::operation::update_documentation_version::builders::UpdateDocumentationVersionInputBuilder::default()
    }
}

/// A builder for [`UpdateDocumentationVersionInput`](crate::operation::update_documentation_version::UpdateDocumentationVersionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDocumentationVersionInputBuilder {
    pub(crate) rest_api_id: ::std::option::Option<::std::string::String>,
    pub(crate) documentation_version: ::std::option::Option<::std::string::String>,
    pub(crate) patch_operations: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>,
}
impl UpdateDocumentationVersionInputBuilder {
    /// <p>The string identifier of the associated RestApi.</p>
    /// This field is required.
    pub fn rest_api_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rest_api_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn set_rest_api_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rest_api_id = input;
        self
    }
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn get_rest_api_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rest_api_id
    }
    /// <p>The version identifier of the to-be-updated documentation version.</p>
    /// This field is required.
    pub fn documentation_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.documentation_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version identifier of the to-be-updated documentation version.</p>
    pub fn set_documentation_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.documentation_version = input;
        self
    }
    /// <p>The version identifier of the to-be-updated documentation version.</p>
    pub fn get_documentation_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.documentation_version
    }
    /// Appends an item to `patch_operations`.
    ///
    /// To override the contents of this collection use [`set_patch_operations`](Self::set_patch_operations).
    ///
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub fn patch_operations(mut self, input: crate::types::PatchOperation) -> Self {
        let mut v = self.patch_operations.unwrap_or_default();
        v.push(input);
        self.patch_operations = ::std::option::Option::Some(v);
        self
    }
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub fn set_patch_operations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>) -> Self {
        self.patch_operations = input;
        self
    }
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub fn get_patch_operations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>> {
        &self.patch_operations
    }
    /// Consumes the builder and constructs a [`UpdateDocumentationVersionInput`](crate::operation::update_documentation_version::UpdateDocumentationVersionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_documentation_version::UpdateDocumentationVersionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_documentation_version::UpdateDocumentationVersionInput {
            rest_api_id: self.rest_api_id,
            documentation_version: self.documentation_version,
            patch_operations: self.patch_operations,
        })
    }
}
