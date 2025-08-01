// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSolFunctionPackageDescriptorOutput {
    /// <p>Indicates the media type of the resource.</p>
    pub content_type: ::std::option::Option<crate::types::DescriptorContentType>,
    /// <p>Contents of the function package descriptor.</p>
    pub vnfd: ::std::option::Option<::aws_smithy_types::Blob>,
    _request_id: Option<String>,
}
impl GetSolFunctionPackageDescriptorOutput {
    /// <p>Indicates the media type of the resource.</p>
    pub fn content_type(&self) -> ::std::option::Option<&crate::types::DescriptorContentType> {
        self.content_type.as_ref()
    }
    /// <p>Contents of the function package descriptor.</p>
    pub fn vnfd(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.vnfd.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetSolFunctionPackageDescriptorOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetSolFunctionPackageDescriptorOutput {
    /// Creates a new builder-style object to manufacture [`GetSolFunctionPackageDescriptorOutput`](crate::operation::get_sol_function_package_descriptor::GetSolFunctionPackageDescriptorOutput).
    pub fn builder() -> crate::operation::get_sol_function_package_descriptor::builders::GetSolFunctionPackageDescriptorOutputBuilder {
        crate::operation::get_sol_function_package_descriptor::builders::GetSolFunctionPackageDescriptorOutputBuilder::default()
    }
}

/// A builder for [`GetSolFunctionPackageDescriptorOutput`](crate::operation::get_sol_function_package_descriptor::GetSolFunctionPackageDescriptorOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSolFunctionPackageDescriptorOutputBuilder {
    pub(crate) content_type: ::std::option::Option<crate::types::DescriptorContentType>,
    pub(crate) vnfd: ::std::option::Option<::aws_smithy_types::Blob>,
    _request_id: Option<String>,
}
impl GetSolFunctionPackageDescriptorOutputBuilder {
    /// <p>Indicates the media type of the resource.</p>
    pub fn content_type(mut self, input: crate::types::DescriptorContentType) -> Self {
        self.content_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the media type of the resource.</p>
    pub fn set_content_type(mut self, input: ::std::option::Option<crate::types::DescriptorContentType>) -> Self {
        self.content_type = input;
        self
    }
    /// <p>Indicates the media type of the resource.</p>
    pub fn get_content_type(&self) -> &::std::option::Option<crate::types::DescriptorContentType> {
        &self.content_type
    }
    /// <p>Contents of the function package descriptor.</p>
    pub fn vnfd(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.vnfd = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contents of the function package descriptor.</p>
    pub fn set_vnfd(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.vnfd = input;
        self
    }
    /// <p>Contents of the function package descriptor.</p>
    pub fn get_vnfd(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.vnfd
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetSolFunctionPackageDescriptorOutput`](crate::operation::get_sol_function_package_descriptor::GetSolFunctionPackageDescriptorOutput).
    pub fn build(self) -> crate::operation::get_sol_function_package_descriptor::GetSolFunctionPackageDescriptorOutput {
        crate::operation::get_sol_function_package_descriptor::GetSolFunctionPackageDescriptorOutput {
            content_type: self.content_type,
            vnfd: self.vnfd,
            _request_id: self._request_id,
        }
    }
}
