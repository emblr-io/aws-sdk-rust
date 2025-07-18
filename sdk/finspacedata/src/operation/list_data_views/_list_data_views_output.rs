// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDataViewsOutput {
    /// <p>A token that indicates where a results page should begin.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of Dataviews.</p>
    pub data_views: ::std::option::Option<::std::vec::Vec<crate::types::DataViewSummary>>,
    _request_id: Option<String>,
}
impl ListDataViewsOutput {
    /// <p>A token that indicates where a results page should begin.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of Dataviews.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.data_views.is_none()`.
    pub fn data_views(&self) -> &[crate::types::DataViewSummary] {
        self.data_views.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListDataViewsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListDataViewsOutput {
    /// Creates a new builder-style object to manufacture [`ListDataViewsOutput`](crate::operation::list_data_views::ListDataViewsOutput).
    pub fn builder() -> crate::operation::list_data_views::builders::ListDataViewsOutputBuilder {
        crate::operation::list_data_views::builders::ListDataViewsOutputBuilder::default()
    }
}

/// A builder for [`ListDataViewsOutput`](crate::operation::list_data_views::ListDataViewsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDataViewsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) data_views: ::std::option::Option<::std::vec::Vec<crate::types::DataViewSummary>>,
    _request_id: Option<String>,
}
impl ListDataViewsOutputBuilder {
    /// <p>A token that indicates where a results page should begin.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that indicates where a results page should begin.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that indicates where a results page should begin.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `data_views`.
    ///
    /// To override the contents of this collection use [`set_data_views`](Self::set_data_views).
    ///
    /// <p>A list of Dataviews.</p>
    pub fn data_views(mut self, input: crate::types::DataViewSummary) -> Self {
        let mut v = self.data_views.unwrap_or_default();
        v.push(input);
        self.data_views = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of Dataviews.</p>
    pub fn set_data_views(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataViewSummary>>) -> Self {
        self.data_views = input;
        self
    }
    /// <p>A list of Dataviews.</p>
    pub fn get_data_views(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataViewSummary>> {
        &self.data_views
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListDataViewsOutput`](crate::operation::list_data_views::ListDataViewsOutput).
    pub fn build(self) -> crate::operation::list_data_views::ListDataViewsOutput {
        crate::operation::list_data_views::ListDataViewsOutput {
            next_token: self.next_token,
            data_views: self.data_views,
            _request_id: self._request_id,
        }
    }
}
