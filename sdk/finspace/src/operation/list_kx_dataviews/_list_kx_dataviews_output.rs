// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListKxDataviewsOutput {
    /// <p>The list of kdb dataviews that are currently active for the given database.</p>
    pub kx_dataviews: ::std::option::Option<::std::vec::Vec<crate::types::KxDataviewListEntry>>,
    /// <p>A token that indicates where a results page should begin.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListKxDataviewsOutput {
    /// <p>The list of kdb dataviews that are currently active for the given database.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.kx_dataviews.is_none()`.
    pub fn kx_dataviews(&self) -> &[crate::types::KxDataviewListEntry] {
        self.kx_dataviews.as_deref().unwrap_or_default()
    }
    /// <p>A token that indicates where a results page should begin.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListKxDataviewsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListKxDataviewsOutput {
    /// Creates a new builder-style object to manufacture [`ListKxDataviewsOutput`](crate::operation::list_kx_dataviews::ListKxDataviewsOutput).
    pub fn builder() -> crate::operation::list_kx_dataviews::builders::ListKxDataviewsOutputBuilder {
        crate::operation::list_kx_dataviews::builders::ListKxDataviewsOutputBuilder::default()
    }
}

/// A builder for [`ListKxDataviewsOutput`](crate::operation::list_kx_dataviews::ListKxDataviewsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListKxDataviewsOutputBuilder {
    pub(crate) kx_dataviews: ::std::option::Option<::std::vec::Vec<crate::types::KxDataviewListEntry>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListKxDataviewsOutputBuilder {
    /// Appends an item to `kx_dataviews`.
    ///
    /// To override the contents of this collection use [`set_kx_dataviews`](Self::set_kx_dataviews).
    ///
    /// <p>The list of kdb dataviews that are currently active for the given database.</p>
    pub fn kx_dataviews(mut self, input: crate::types::KxDataviewListEntry) -> Self {
        let mut v = self.kx_dataviews.unwrap_or_default();
        v.push(input);
        self.kx_dataviews = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of kdb dataviews that are currently active for the given database.</p>
    pub fn set_kx_dataviews(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::KxDataviewListEntry>>) -> Self {
        self.kx_dataviews = input;
        self
    }
    /// <p>The list of kdb dataviews that are currently active for the given database.</p>
    pub fn get_kx_dataviews(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::KxDataviewListEntry>> {
        &self.kx_dataviews
    }
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
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListKxDataviewsOutput`](crate::operation::list_kx_dataviews::ListKxDataviewsOutput).
    pub fn build(self) -> crate::operation::list_kx_dataviews::ListKxDataviewsOutput {
        crate::operation::list_kx_dataviews::ListKxDataviewsOutput {
            kx_dataviews: self.kx_dataviews,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
