// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>List exports request filters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListExportsRequestFilters {
    /// <p>List exports request filters export ids.</p>
    pub export_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListExportsRequestFilters {
    /// <p>List exports request filters export ids.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.export_ids.is_none()`.
    pub fn export_ids(&self) -> &[::std::string::String] {
        self.export_ids.as_deref().unwrap_or_default()
    }
}
impl ListExportsRequestFilters {
    /// Creates a new builder-style object to manufacture [`ListExportsRequestFilters`](crate::types::ListExportsRequestFilters).
    pub fn builder() -> crate::types::builders::ListExportsRequestFiltersBuilder {
        crate::types::builders::ListExportsRequestFiltersBuilder::default()
    }
}

/// A builder for [`ListExportsRequestFilters`](crate::types::ListExportsRequestFilters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListExportsRequestFiltersBuilder {
    pub(crate) export_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListExportsRequestFiltersBuilder {
    /// Appends an item to `export_ids`.
    ///
    /// To override the contents of this collection use [`set_export_ids`](Self::set_export_ids).
    ///
    /// <p>List exports request filters export ids.</p>
    pub fn export_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.export_ids.unwrap_or_default();
        v.push(input.into());
        self.export_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>List exports request filters export ids.</p>
    pub fn set_export_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.export_ids = input;
        self
    }
    /// <p>List exports request filters export ids.</p>
    pub fn get_export_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.export_ids
    }
    /// Consumes the builder and constructs a [`ListExportsRequestFilters`](crate::types::ListExportsRequestFilters).
    pub fn build(self) -> crate::types::ListExportsRequestFilters {
        crate::types::ListExportsRequestFilters { export_ids: self.export_ids }
    }
}
