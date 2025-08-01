// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains a paginated list of activity type information structures.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListActivityTypesOutput {
    /// <p>List of activity type information.</p>
    pub type_infos: ::std::vec::Vec<crate::types::ActivityTypeInfo>,
    /// <p>If a <code>NextPageToken</code> was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in <code>nextPageToken</code>. Keep all other arguments unchanged.</p>
    /// <p>The configured <code>maximumPageSize</code> determines how many results can be returned in a single call.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListActivityTypesOutput {
    /// <p>List of activity type information.</p>
    pub fn type_infos(&self) -> &[crate::types::ActivityTypeInfo] {
        use std::ops::Deref;
        self.type_infos.deref()
    }
    /// <p>If a <code>NextPageToken</code> was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in <code>nextPageToken</code>. Keep all other arguments unchanged.</p>
    /// <p>The configured <code>maximumPageSize</code> determines how many results can be returned in a single call.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListActivityTypesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListActivityTypesOutput {
    /// Creates a new builder-style object to manufacture [`ListActivityTypesOutput`](crate::operation::list_activity_types::ListActivityTypesOutput).
    pub fn builder() -> crate::operation::list_activity_types::builders::ListActivityTypesOutputBuilder {
        crate::operation::list_activity_types::builders::ListActivityTypesOutputBuilder::default()
    }
}

/// A builder for [`ListActivityTypesOutput`](crate::operation::list_activity_types::ListActivityTypesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListActivityTypesOutputBuilder {
    pub(crate) type_infos: ::std::option::Option<::std::vec::Vec<crate::types::ActivityTypeInfo>>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListActivityTypesOutputBuilder {
    /// Appends an item to `type_infos`.
    ///
    /// To override the contents of this collection use [`set_type_infos`](Self::set_type_infos).
    ///
    /// <p>List of activity type information.</p>
    pub fn type_infos(mut self, input: crate::types::ActivityTypeInfo) -> Self {
        let mut v = self.type_infos.unwrap_or_default();
        v.push(input);
        self.type_infos = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of activity type information.</p>
    pub fn set_type_infos(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ActivityTypeInfo>>) -> Self {
        self.type_infos = input;
        self
    }
    /// <p>List of activity type information.</p>
    pub fn get_type_infos(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ActivityTypeInfo>> {
        &self.type_infos
    }
    /// <p>If a <code>NextPageToken</code> was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in <code>nextPageToken</code>. Keep all other arguments unchanged.</p>
    /// <p>The configured <code>maximumPageSize</code> determines how many results can be returned in a single call.</p>
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If a <code>NextPageToken</code> was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in <code>nextPageToken</code>. Keep all other arguments unchanged.</p>
    /// <p>The configured <code>maximumPageSize</code> determines how many results can be returned in a single call.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>If a <code>NextPageToken</code> was returned by a previous call, there are more results available. To retrieve the next page of results, make the call again using the returned token in <code>nextPageToken</code>. Keep all other arguments unchanged.</p>
    /// <p>The configured <code>maximumPageSize</code> determines how many results can be returned in a single call.</p>
    pub fn get_next_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_page_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListActivityTypesOutput`](crate::operation::list_activity_types::ListActivityTypesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`type_infos`](crate::operation::list_activity_types::builders::ListActivityTypesOutputBuilder::type_infos)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_activity_types::ListActivityTypesOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_activity_types::ListActivityTypesOutput {
            type_infos: self.type_infos.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "type_infos",
                    "type_infos was not specified but it is required when building ListActivityTypesOutput",
                )
            })?,
            next_page_token: self.next_page_token,
            _request_id: self._request_id,
        })
    }
}
