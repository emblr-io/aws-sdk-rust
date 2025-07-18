// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ImportCatalogToGlueOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for ImportCatalogToGlueOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ImportCatalogToGlueOutput {
    /// Creates a new builder-style object to manufacture [`ImportCatalogToGlueOutput`](crate::operation::import_catalog_to_glue::ImportCatalogToGlueOutput).
    pub fn builder() -> crate::operation::import_catalog_to_glue::builders::ImportCatalogToGlueOutputBuilder {
        crate::operation::import_catalog_to_glue::builders::ImportCatalogToGlueOutputBuilder::default()
    }
}

/// A builder for [`ImportCatalogToGlueOutput`](crate::operation::import_catalog_to_glue::ImportCatalogToGlueOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ImportCatalogToGlueOutputBuilder {
    _request_id: Option<String>,
}
impl ImportCatalogToGlueOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ImportCatalogToGlueOutput`](crate::operation::import_catalog_to_glue::ImportCatalogToGlueOutput).
    pub fn build(self) -> crate::operation::import_catalog_to_glue::ImportCatalogToGlueOutput {
        crate::operation::import_catalog_to_glue::ImportCatalogToGlueOutput {
            _request_id: self._request_id,
        }
    }
}
