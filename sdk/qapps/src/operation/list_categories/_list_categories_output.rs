// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCategoriesOutput {
    /// <p>The categories of a Amazon Q Business application environment instance.</p>
    pub categories: ::std::option::Option<::std::vec::Vec<crate::types::Category>>,
    _request_id: Option<String>,
}
impl ListCategoriesOutput {
    /// <p>The categories of a Amazon Q Business application environment instance.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.categories.is_none()`.
    pub fn categories(&self) -> &[crate::types::Category] {
        self.categories.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListCategoriesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListCategoriesOutput {
    /// Creates a new builder-style object to manufacture [`ListCategoriesOutput`](crate::operation::list_categories::ListCategoriesOutput).
    pub fn builder() -> crate::operation::list_categories::builders::ListCategoriesOutputBuilder {
        crate::operation::list_categories::builders::ListCategoriesOutputBuilder::default()
    }
}

/// A builder for [`ListCategoriesOutput`](crate::operation::list_categories::ListCategoriesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCategoriesOutputBuilder {
    pub(crate) categories: ::std::option::Option<::std::vec::Vec<crate::types::Category>>,
    _request_id: Option<String>,
}
impl ListCategoriesOutputBuilder {
    /// Appends an item to `categories`.
    ///
    /// To override the contents of this collection use [`set_categories`](Self::set_categories).
    ///
    /// <p>The categories of a Amazon Q Business application environment instance.</p>
    pub fn categories(mut self, input: crate::types::Category) -> Self {
        let mut v = self.categories.unwrap_or_default();
        v.push(input);
        self.categories = ::std::option::Option::Some(v);
        self
    }
    /// <p>The categories of a Amazon Q Business application environment instance.</p>
    pub fn set_categories(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Category>>) -> Self {
        self.categories = input;
        self
    }
    /// <p>The categories of a Amazon Q Business application environment instance.</p>
    pub fn get_categories(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Category>> {
        &self.categories
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListCategoriesOutput`](crate::operation::list_categories::ListCategoriesOutput).
    pub fn build(self) -> crate::operation::list_categories::ListCategoriesOutput {
        crate::operation::list_categories::ListCategoriesOutput {
            categories: self.categories,
            _request_id: self._request_id,
        }
    }
}
