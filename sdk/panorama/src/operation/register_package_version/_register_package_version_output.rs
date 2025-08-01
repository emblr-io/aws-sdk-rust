// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterPackageVersionOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for RegisterPackageVersionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RegisterPackageVersionOutput {
    /// Creates a new builder-style object to manufacture [`RegisterPackageVersionOutput`](crate::operation::register_package_version::RegisterPackageVersionOutput).
    pub fn builder() -> crate::operation::register_package_version::builders::RegisterPackageVersionOutputBuilder {
        crate::operation::register_package_version::builders::RegisterPackageVersionOutputBuilder::default()
    }
}

/// A builder for [`RegisterPackageVersionOutput`](crate::operation::register_package_version::RegisterPackageVersionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterPackageVersionOutputBuilder {
    _request_id: Option<String>,
}
impl RegisterPackageVersionOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RegisterPackageVersionOutput`](crate::operation::register_package_version::RegisterPackageVersionOutput).
    pub fn build(self) -> crate::operation::register_package_version::RegisterPackageVersionOutput {
        crate::operation::register_package_version::RegisterPackageVersionOutput {
            _request_id: self._request_id,
        }
    }
}
