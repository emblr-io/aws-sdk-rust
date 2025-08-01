// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePackageVersionOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeletePackageVersionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeletePackageVersionOutput {
    /// Creates a new builder-style object to manufacture [`DeletePackageVersionOutput`](crate::operation::delete_package_version::DeletePackageVersionOutput).
    pub fn builder() -> crate::operation::delete_package_version::builders::DeletePackageVersionOutputBuilder {
        crate::operation::delete_package_version::builders::DeletePackageVersionOutputBuilder::default()
    }
}

/// A builder for [`DeletePackageVersionOutput`](crate::operation::delete_package_version::DeletePackageVersionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePackageVersionOutputBuilder {
    _request_id: Option<String>,
}
impl DeletePackageVersionOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeletePackageVersionOutput`](crate::operation::delete_package_version::DeletePackageVersionOutput).
    pub fn build(self) -> crate::operation::delete_package_version::DeletePackageVersionOutput {
        crate::operation::delete_package_version::DeletePackageVersionOutput {
            _request_id: self._request_id,
        }
    }
}
