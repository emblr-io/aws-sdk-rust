// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTagOptionsInput {
    /// <p>The search filters. If no search filters are specified, the output includes all TagOptions.</p>
    pub filters: ::std::option::Option<crate::types::ListTagOptionsFilters>,
    /// <p>The maximum number of items to return with this call.</p>
    pub page_size: ::std::option::Option<i32>,
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub page_token: ::std::option::Option<::std::string::String>,
}
impl ListTagOptionsInput {
    /// <p>The search filters. If no search filters are specified, the output includes all TagOptions.</p>
    pub fn filters(&self) -> ::std::option::Option<&crate::types::ListTagOptionsFilters> {
        self.filters.as_ref()
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn page_size(&self) -> ::std::option::Option<i32> {
        self.page_size
    }
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub fn page_token(&self) -> ::std::option::Option<&str> {
        self.page_token.as_deref()
    }
}
impl ListTagOptionsInput {
    /// Creates a new builder-style object to manufacture [`ListTagOptionsInput`](crate::operation::list_tag_options::ListTagOptionsInput).
    pub fn builder() -> crate::operation::list_tag_options::builders::ListTagOptionsInputBuilder {
        crate::operation::list_tag_options::builders::ListTagOptionsInputBuilder::default()
    }
}

/// A builder for [`ListTagOptionsInput`](crate::operation::list_tag_options::ListTagOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTagOptionsInputBuilder {
    pub(crate) filters: ::std::option::Option<crate::types::ListTagOptionsFilters>,
    pub(crate) page_size: ::std::option::Option<i32>,
    pub(crate) page_token: ::std::option::Option<::std::string::String>,
}
impl ListTagOptionsInputBuilder {
    /// <p>The search filters. If no search filters are specified, the output includes all TagOptions.</p>
    pub fn filters(mut self, input: crate::types::ListTagOptionsFilters) -> Self {
        self.filters = ::std::option::Option::Some(input);
        self
    }
    /// <p>The search filters. If no search filters are specified, the output includes all TagOptions.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<crate::types::ListTagOptionsFilters>) -> Self {
        self.filters = input;
        self
    }
    /// <p>The search filters. If no search filters are specified, the output includes all TagOptions.</p>
    pub fn get_filters(&self) -> &::std::option::Option<crate::types::ListTagOptionsFilters> {
        &self.filters
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn page_size(mut self, input: i32) -> Self {
        self.page_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn set_page_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.page_size = input;
        self
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn get_page_size(&self) -> &::std::option::Option<i32> {
        &self.page_size
    }
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub fn page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub fn set_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.page_token = input;
        self
    }
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub fn get_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.page_token
    }
    /// Consumes the builder and constructs a [`ListTagOptionsInput`](crate::operation::list_tag_options::ListTagOptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_tag_options::ListTagOptionsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_tag_options::ListTagOptionsInput {
            filters: self.filters,
            page_size: self.page_size,
            page_token: self.page_token,
        })
    }
}
