// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents an update integration response request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateIntegrationResponseInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub rest_api_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies an update integration response request's resource identifier.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies an update integration response request's HTTP method.</p>
    pub http_method: ::std::option::Option<::std::string::String>,
    /// <p>Specifies an update integration response request's status code.</p>
    pub status_code: ::std::option::Option<::std::string::String>,
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    pub patch_operations: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>,
}
impl UpdateIntegrationResponseInput {
    /// <p>The string identifier of the associated RestApi.</p>
    pub fn rest_api_id(&self) -> ::std::option::Option<&str> {
        self.rest_api_id.as_deref()
    }
    /// <p>Specifies an update integration response request's resource identifier.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>Specifies an update integration response request's HTTP method.</p>
    pub fn http_method(&self) -> ::std::option::Option<&str> {
        self.http_method.as_deref()
    }
    /// <p>Specifies an update integration response request's status code.</p>
    pub fn status_code(&self) -> ::std::option::Option<&str> {
        self.status_code.as_deref()
    }
    /// <p>For more information about supported patch operations, see <a href="https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html">Patch Operations</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.patch_operations.is_none()`.
    pub fn patch_operations(&self) -> &[crate::types::PatchOperation] {
        self.patch_operations.as_deref().unwrap_or_default()
    }
}
impl UpdateIntegrationResponseInput {
    /// Creates a new builder-style object to manufacture [`UpdateIntegrationResponseInput`](crate::operation::update_integration_response::UpdateIntegrationResponseInput).
    pub fn builder() -> crate::operation::update_integration_response::builders::UpdateIntegrationResponseInputBuilder {
        crate::operation::update_integration_response::builders::UpdateIntegrationResponseInputBuilder::default()
    }
}

/// A builder for [`UpdateIntegrationResponseInput`](crate::operation::update_integration_response::UpdateIntegrationResponseInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateIntegrationResponseInputBuilder {
    pub(crate) rest_api_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) http_method: ::std::option::Option<::std::string::String>,
    pub(crate) status_code: ::std::option::Option<::std::string::String>,
    pub(crate) patch_operations: ::std::option::Option<::std::vec::Vec<crate::types::PatchOperation>>,
}
impl UpdateIntegrationResponseInputBuilder {
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
    /// <p>Specifies an update integration response request's resource identifier.</p>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies an update integration response request's resource identifier.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>Specifies an update integration response request's resource identifier.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>Specifies an update integration response request's HTTP method.</p>
    /// This field is required.
    pub fn http_method(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.http_method = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies an update integration response request's HTTP method.</p>
    pub fn set_http_method(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.http_method = input;
        self
    }
    /// <p>Specifies an update integration response request's HTTP method.</p>
    pub fn get_http_method(&self) -> &::std::option::Option<::std::string::String> {
        &self.http_method
    }
    /// <p>Specifies an update integration response request's status code.</p>
    /// This field is required.
    pub fn status_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies an update integration response request's status code.</p>
    pub fn set_status_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_code = input;
        self
    }
    /// <p>Specifies an update integration response request's status code.</p>
    pub fn get_status_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_code
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
    /// Consumes the builder and constructs a [`UpdateIntegrationResponseInput`](crate::operation::update_integration_response::UpdateIntegrationResponseInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_integration_response::UpdateIntegrationResponseInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_integration_response::UpdateIntegrationResponseInput {
            rest_api_id: self.rest_api_id,
            resource_id: self.resource_id,
            http_method: self.http_method,
            status_code: self.status_code,
            patch_operations: self.patch_operations,
        })
    }
}
