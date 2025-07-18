// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListHapgsOutput {
    /// <p>The list of high-availability partition groups.</p>
    pub hapg_list: ::std::vec::Vec<::std::string::String>,
    /// <p>If not null, more results are available. Pass this value to <code>ListHapgs</code> to retrieve the next set of items.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListHapgsOutput {
    /// <p>The list of high-availability partition groups.</p>
    pub fn hapg_list(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.hapg_list.deref()
    }
    /// <p>If not null, more results are available. Pass this value to <code>ListHapgs</code> to retrieve the next set of items.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListHapgsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListHapgsOutput {
    /// Creates a new builder-style object to manufacture [`ListHapgsOutput`](crate::operation::list_hapgs::ListHapgsOutput).
    pub fn builder() -> crate::operation::list_hapgs::builders::ListHapgsOutputBuilder {
        crate::operation::list_hapgs::builders::ListHapgsOutputBuilder::default()
    }
}

/// A builder for [`ListHapgsOutput`](crate::operation::list_hapgs::ListHapgsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListHapgsOutputBuilder {
    pub(crate) hapg_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListHapgsOutputBuilder {
    /// Appends an item to `hapg_list`.
    ///
    /// To override the contents of this collection use [`set_hapg_list`](Self::set_hapg_list).
    ///
    /// <p>The list of high-availability partition groups.</p>
    pub fn hapg_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.hapg_list.unwrap_or_default();
        v.push(input.into());
        self.hapg_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of high-availability partition groups.</p>
    pub fn set_hapg_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.hapg_list = input;
        self
    }
    /// <p>The list of high-availability partition groups.</p>
    pub fn get_hapg_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.hapg_list
    }
    /// <p>If not null, more results are available. Pass this value to <code>ListHapgs</code> to retrieve the next set of items.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If not null, more results are available. Pass this value to <code>ListHapgs</code> to retrieve the next set of items.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If not null, more results are available. Pass this value to <code>ListHapgs</code> to retrieve the next set of items.</p>
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
    /// Consumes the builder and constructs a [`ListHapgsOutput`](crate::operation::list_hapgs::ListHapgsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`hapg_list`](crate::operation::list_hapgs::builders::ListHapgsOutputBuilder::hapg_list)
    pub fn build(self) -> ::std::result::Result<crate::operation::list_hapgs::ListHapgsOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_hapgs::ListHapgsOutput {
            hapg_list: self.hapg_list.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "hapg_list",
                    "hapg_list was not specified but it is required when building ListHapgsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
