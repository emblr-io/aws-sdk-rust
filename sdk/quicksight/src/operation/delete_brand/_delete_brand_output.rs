// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteBrandOutput {
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteBrandOutput {
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteBrandOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteBrandOutput {
    /// Creates a new builder-style object to manufacture [`DeleteBrandOutput`](crate::operation::delete_brand::DeleteBrandOutput).
    pub fn builder() -> crate::operation::delete_brand::builders::DeleteBrandOutputBuilder {
        crate::operation::delete_brand::builders::DeleteBrandOutputBuilder::default()
    }
}

/// A builder for [`DeleteBrandOutput`](crate::operation::delete_brand::DeleteBrandOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteBrandOutputBuilder {
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteBrandOutputBuilder {
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteBrandOutput`](crate::operation::delete_brand::DeleteBrandOutput).
    pub fn build(self) -> crate::operation::delete_brand::DeleteBrandOutput {
        crate::operation::delete_brand::DeleteBrandOutput {
            request_id: self.request_id,
            _request_id: self._request_id,
        }
    }
}
