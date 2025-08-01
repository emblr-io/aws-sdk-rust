// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetResourceSetOutput {
    /// <p>Information about the specified resource set.</p>
    pub resource_set: ::std::option::Option<crate::types::ResourceSet>,
    /// <p>The Amazon Resource Name (ARN) of the resource set.</p>
    pub resource_set_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl GetResourceSetOutput {
    /// <p>Information about the specified resource set.</p>
    pub fn resource_set(&self) -> ::std::option::Option<&crate::types::ResourceSet> {
        self.resource_set.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the resource set.</p>
    pub fn resource_set_arn(&self) -> &str {
        use std::ops::Deref;
        self.resource_set_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for GetResourceSetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetResourceSetOutput {
    /// Creates a new builder-style object to manufacture [`GetResourceSetOutput`](crate::operation::get_resource_set::GetResourceSetOutput).
    pub fn builder() -> crate::operation::get_resource_set::builders::GetResourceSetOutputBuilder {
        crate::operation::get_resource_set::builders::GetResourceSetOutputBuilder::default()
    }
}

/// A builder for [`GetResourceSetOutput`](crate::operation::get_resource_set::GetResourceSetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetResourceSetOutputBuilder {
    pub(crate) resource_set: ::std::option::Option<crate::types::ResourceSet>,
    pub(crate) resource_set_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetResourceSetOutputBuilder {
    /// <p>Information about the specified resource set.</p>
    /// This field is required.
    pub fn resource_set(mut self, input: crate::types::ResourceSet) -> Self {
        self.resource_set = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the specified resource set.</p>
    pub fn set_resource_set(mut self, input: ::std::option::Option<crate::types::ResourceSet>) -> Self {
        self.resource_set = input;
        self
    }
    /// <p>Information about the specified resource set.</p>
    pub fn get_resource_set(&self) -> &::std::option::Option<crate::types::ResourceSet> {
        &self.resource_set
    }
    /// <p>The Amazon Resource Name (ARN) of the resource set.</p>
    /// This field is required.
    pub fn resource_set_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_set_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource set.</p>
    pub fn set_resource_set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_set_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource set.</p>
    pub fn get_resource_set_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_set_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetResourceSetOutput`](crate::operation::get_resource_set::GetResourceSetOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`resource_set_arn`](crate::operation::get_resource_set::builders::GetResourceSetOutputBuilder::resource_set_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_resource_set::GetResourceSetOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_resource_set::GetResourceSetOutput {
            resource_set: self.resource_set,
            resource_set_arn: self.resource_set_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_set_arn",
                    "resource_set_arn was not specified but it is required when building GetResourceSetOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
