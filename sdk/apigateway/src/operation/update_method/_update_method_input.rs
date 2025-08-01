// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request to update an existing Method resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateMethodInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub rest_api_id: ::std::option::Option<::std::string::String>,
    /// <p>The Resource identifier for the Method resource.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>The HTTP verb of the Method resource.</p>
    pub http_method: ::std::option::Option<::std::string::String>,
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub patch_operations: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>,
}
impl UpdateMethodInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn rest_api_id(&self) -> ::std::option::Option<&str> {
        self.rest_api_id.as_deref()
    }
    /// <p>The Resource identifier for the Method resource.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>The HTTP verb of the Method resource.</p>
    pub fn http_method(&self) -> ::std::option::Option<&str> {
        self.http_method.as_deref()
    }
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.patch_operations.is_none()`.
    pub fn patch_operations(&self) -> &[crate::types::PatchOperation] {
        self.patch_operations.as_deref().unwrap_or_default()
    }
}
impl UpdateMethodInput {
    /// Creates a new builder-style object to manufacture [`UpdateMethodInput`](crate::operation::update_method::UpdateMethodInput).
    pub fn builder() -> crate::operation::update_method::builders::UpdateMethodInputBuilder {
        crate::operation::update_method::builders::UpdateMethodInputBuilder::default()
    }
}

/// A builder for [`UpdateMethodInput`](crate::operation::update_method::UpdateMethodInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateMethodInputBuilder {
    pub(crate) rest_api_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) http_method: ::std::option::Option<::std::string::String>,
    pub(crate) patch_operations: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>,
}
impl UpdateMethodInputBuilder {
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
    /// <p>The Resource identifier for the Method resource.</p>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Resource identifier for the Method resource.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The Resource identifier for the Method resource.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>The HTTP verb of the Method resource.</p>
    /// This field is required.
    pub fn http_method(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.http_method = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The HTTP verb of the Method resource.</p>
    pub fn set_http_method(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.http_method = input;
        self
    }
    /// <p>The HTTP verb of the Method resource.</p>
    pub fn get_http_method(&self) -> &::std::option::Option<::std::string::String> {
        &self.http_method
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
    /// Consumes the builder and constructs a [`UpdateMethodInput`](crate::operation::update_method::UpdateMethodInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_method::UpdateMethodInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_method::UpdateMethodInput {
            rest_api_id: self.rest_api_id,
            resource_id: self.resource_id,
            http_method: self.http_method,
            patch_operations: self.patch_operations,
        })
    }
}
